//
//  StravaClient.swift
//  StravaSwift
//
//  Created by Matthew on 11/11/2015.
//  Copyright © 2015 Matthew Clarkson. All rights reserved.
//

import Alamofire
import AuthenticationServices
import Foundation

import SwiftyJSON

#if canImport(SafariServices)
import SafariServices
#endif


/**
 StravaClient responsible for making all api requests
*/

public struct StravaSwiftAuth: Codable {

    public init(token: OAuthToken) {
        self.token = token
    }

    public var token: OAuthToken
}

open class StravaClient: NSObject {

    /**
     Access the shared instance
     */
    public static let sharedInstance = StravaClient()

    fileprivate override init() {}
    fileprivate var config: StravaConfig?

    public typealias AuthorizationHandler = (Swift.Result<OAuthToken, Error>) -> Void
    fileprivate var currentAuthorizationHandler: AuthorizationHandler?
    fileprivate var authSession: NSObject?  // Holds a reference to ASWebAuthenticationSession / SFAuthenticationSession depending on iOS version

    private var currentAuth: StravaSwiftAuth?

    /// Public read-only access to the current token
    public var token: OAuthToken? {
        return currentAuth?.token
    }

    /// Updates the client's authentication state
    public func setAuth(_ auth: StravaSwiftAuth) {
        self.currentAuth = auth
    }

    /// Clears the current authentication state
    public func clearAuth() {
        self.currentAuth = nil
    }

    var authContinuation: CheckedContinuation<URL, Never>?

    /**
      The OAuthToken returned by the delegate
     **/
    // open var token:  OAuthToken? { return config?.delegate.get() }

    internal var authParams: [String: Any] {
        return [
            "client_id": config?.clientId ?? 0,
            "redirect_uri": config?.redirectUri ?? "",
            "scope": (config?.scopes ?? []).map { $0.rawValue }.joined(separator: ","),
            "state": "ios" as AnyObject,
            "approval_prompt": config?.forcePrompt ?? true ? "force" : "auto",
            "response_type": "code",
        ]
    }

    internal func tokenParams(_ code: String) -> [String: Any] {
        return [
            "client_id": config?.clientId ?? 0,
            "client_secret": config?.clientSecret ?? "",
            "code": code,
        ]
    }

    internal func refreshParams(_ refreshToken: String) -> [String: Any] {
        return [
            "client_id": config?.clientId ?? 0,
            "client_secret": config?.clientSecret ?? "",
            "grant_type": "refresh_token",
            "refresh_token": refreshToken,
        ]
    }
}

//MARK:varConfig

extension StravaClient {

    /**
     Initialize the shared instance with your credentials. You must use this otherwise fatal errors will be
     returned when making api requests.

     - Parameter config: a StravaConfig struct
     - Returns: An instance of self (i.e. StravaClient)
     */
    public func initWithConfig(_ config: StravaConfig) -> StravaClient {
        self.config = config

        return self
    }
}

//MARK: - Auth Async ( + Dean's additions)

extension StravaClient {
    
    @MainActor
    public func handleAuthURL(_ url: URL) {
        self.authContinuation?.resume(returning: url)
        self.authContinuation = nil
    }

    func getAccessToken(from url: URL) async -> OAuthToken? {

        guard let code = url.getQueryParameters()?["code"] else { return nil }

        do {
            return try await getAccessToken(code)
        } catch {
            return nil
        }
    }

    private func getAccessToken(_ code: String) async throws -> OAuthToken {

        let token = try await withCheckedThrowingContinuation { continuation in
            do {
                let request = try oauthRequest(Router.token(code: code))

                request?.responseStrava { (response: DataResponse<OAuthToken>) in
                    switch response.result {
                    case .success(let token):
                        continuation.resume(returning: token)
                        return

                    case .failure(let error):
                        // Assuming error is of a type that can be thrown
                        continuation.resume(throwing: error)
                        return
                    }
                }
            } catch {
                continuation.resume(throwing: error)
                return
            }
        }

        return token
    }

    private func getScopes(from url: URL) -> [Scope] {
        guard let encodedScopes = url.getQueryParameters()?["scope"],
              let decodedScopes = encodedScopes.removingPercentEncoding
        else {
            return []
        }
        
        let parts = decodedScopes.split(separator: ",").map(String.init)
        let scopes = parts.compactMap { Scope(rawValue: $0) }
//        print("Parsed scopes:", scopes)
        
        return scopes
    }

    @MainActor
    public func refreshToken(_ refreshToken: String) async throws -> OAuthToken {

        let token = try await withCheckedThrowingContinuation { continuation in

            do {
                let request = try oauthRequest(Router.refresh(refreshToken: refreshToken))

                request?.responseStrava { (response: DataResponse<OAuthToken>) in

                    if let token = response.result.value, token.accessToken != nil {
                        continuation.resume(returning: token)

                        return
                    } else {
                        if let error = response.error {
                            continuation.resume(throwing: error)
                            return
                        } else {
                            continuation.resume(throwing: StravaClientError.tokenRetrievalFailed)
                            return
                        }
                    }
                }
            } catch {
                continuation.resume(throwing: error)
                return
            }
        }

        return token
    }
}

//MARK: - Athlete Async

extension StravaClient {

    public func getAthlete() async throws -> Athlete {

        let athlete = try await withCheckedThrowingContinuation { continuation in

            request(
                Router.athlete,
                result: { (athlete: Athlete?) in
                    //                for bike in athlete?.bikes ?? [] {
                    //                    print("Got bikes? Bike ID:", bike.id)
                    //                }
                    continuation.resume(returning: athlete)
                    return

                },
                failure: { (error: NSError) in
                    continuation.resume(throwing: error)
                    return
                })
        }

        if let athlete {
            return athlete
        } else {
            throw self.generateError(failureReason: "Athlete not found", response: nil)
        }
    }

    public func getBikesForAthlete(athlete: Athlete) async throws -> [Bike] {

        guard let bikes = athlete.bikes else { return [] }

        var tempBikes: [Bike] = []

        for bike in bikes {

            guard let bikeID = bike.id else { continue }

            let detailedBike: Bike? = try await withCheckedThrowingContinuation { continuation in
                request(
                    Router.gear(id: bikeID),
                    result: { (bike: Bike?) in
                        continuation.resume(returning: bike)
                        return

                    },
                    failure: { (error: NSError) in
                        continuation.resume(throwing: error)
                        return
                    })
            }

            if let detailedBike {
                tempBikes.append(detailedBike)
            }
        }

        return tempBikes
    }
}

//MARK: - Athlete

extension StravaClient {

    public func uploadAsync(_ upload: UploadData) async throws -> UploadStatus {
        return try await withCheckedThrowingContinuation { continuation in
            self.upload(Router.uploadFile(upload: upload), upload: upload) {
                (status: UploadStatus?) in
                if let status = status {
                    continuation.resume(returning: status)
                } else {
                    continuation.resume(
                        throwing: self.generateError(
                            failureReason: "Strava API Error", response: nil))
                }
            } failure: { error in
                continuation.resume(throwing: error)
            }
        }
    }

    public func checkUploadStatusAsync(_ uploadId: Int) async throws -> UploadStatus {
        return try await withCheckedThrowingContinuation { continuation in
            self.request(Router.uploads(id: uploadId)) { (status: UploadStatus?) in
                if let status = status {
                    continuation.resume(returning: status)
                } else {
                    continuation.resume(
                        throwing: self.generateError(
                            failureReason: "Strava API Error", response: nil))
                }
            } failure: { error in
                continuation.resume(throwing: error)
            }
        }
    }

    public func deauthorizeAsync(accessToken: String) async throws {
        try await withCheckedThrowingContinuation { continuation in
            print("deauth Strava with token: \(accessToken)")
            self.request(Router.deauthorize(accessToken: accessToken)) { (result: OAuthToken?) in
                // Successful deauthorization
                continuation.resume()
            } failure: { error in
                print("ooopsie error:", error)
                continuation.resume(throwing: error)
            }
        }
    }

    public func upload<T: Strava>(
        _ route: Router, upload: UploadData, result: @escaping (((T)?) -> Void),
        failure: @escaping (NSError) -> Void
    ) {
        do {
            try oauthUpload(URLRequest: route.asURLRequest(), upload: upload) {
                (response: DataResponse<T>) in
                if let statusCode = response.response?.statusCode, (400..<500).contains(statusCode)
                {
                    failure(
                        self.generateError(
                            failureReason: "Strava API Error", response: response.response))
                } else {
                    result(response.result.value)
                }
            }
        } catch let error as NSError {
            failure(error)
        }
    }

    /**
     Request a single object from the Strava Api

     - Parameter route: a Router enum case which may require parameters
     - Parameter result: a closure to handle the returned object
     **/
    public func request<T: Strava>(
        _ route: Router, result: @escaping (((T)?) -> Void), failure: @escaping (NSError) -> Void
    ) {
        do {
            try oauthRequest(route)?.responseStrava { (response: DataResponse<T>) in

                //                if let data = response.data {
                //                    do {
                //                        let json = try JSONSerialization.jsonObject(with: data, options: .mutableContainers)
                //                        print("Raw JSON response: \(json)")
                //                    } catch {
                //                        print("Failed to decode JSON: \(error)")
                //                    }
                //                }

                // HTTP Status codes above 400 are errors
                if let statusCode = response.response?.statusCode, (400..<500).contains(statusCode)
                {
                    failure(
                        self.generateError(
                            failureReason: "Strava API Error", response: response.response))
                } else {
                    result(response.result.value)
                }
            }
        } catch let error as NSError {
            failure(error)
        }
    }

    /**
     Request an array of objects from the Strava Api

     - Parameter route: a Router enum case which may require parameters
     - Parameter result: a closure to handle the returned objects
     **/
    public func request<T: Strava>(
        _ route: Router, result: @escaping ((([T])?) -> Void), failure: @escaping (NSError) -> Void
    ) {
        do {
            try oauthRequest(route)?.responseStravaArray { (response: DataResponse<[T]>) in
                // HTTP Status codes above 400 are errors
                if let statusCode = response.response?.statusCode, (400..<500).contains(statusCode)
                {
                    failure(
                        self.generateError(
                            failureReason: "Strava API Error", response: response.response))
                } else {
                    result(response.result.value)
                }
            }
        } catch let error as NSError {
            failure(error)
        }
    }

    fileprivate func generateError(failureReason: String, response: HTTPURLResponse?) -> NSError {
        let errorDomain = "com.stravaswift.error"
        let userInfo = [NSLocalizedFailureReasonErrorKey: failureReason]
        let code = response?.statusCode ?? 0
        let returnError = NSError(domain: errorDomain, code: code, userInfo: userInfo)

        return returnError
    }

}

extension StravaClient {

    fileprivate func isConfigured() -> (Bool) {
        return config != nil
    }

    fileprivate func checkConfiguration() {
        if !isConfigured() {
            fatalError("Strava client is not configured")
        }
    }

    fileprivate func oauthRequest(_ urlRequest: URLRequestConvertible) throws -> DataRequest? {
        checkConfiguration()

        return Alamofire.request(urlRequest)
    }

    fileprivate func oauthUpload<T: Strava>(
        URLRequest: URLRequestConvertible, upload: UploadData,
        completion: @escaping (DataResponse<T>) -> Void
    ) {
        checkConfiguration()

        guard let url = try? URLRequest.asURLRequest() else { return }

        Alamofire.upload(
            multipartFormData: { multipartFormData in
                multipartFormData.append(
                    upload.file, withName: "file",
                    fileName: "\(upload.name ?? "default").\(upload.dataType)",
                    mimeType: "octet/stream")
                for (key, value) in upload.params {
                    if let value = value as? String {
                        multipartFormData.append(value.data(using: .utf8)!, withName: key)
                    }
                }
            }, usingThreshold: SessionManager.multipartFormDataEncodingMemoryThreshold, with: url
        ) { encodingResult in
            switch encodingResult {
            case .success(let upload, _, _):
                upload.responseStrava { (response: DataResponse<T>) in
                    completion(response)
                }
            case .failure(let encodingError):
                print(encodingError)
            }
        }
    }
}

// MARK: iOS-Only
#if os(iOS)
//MARK: - Auth
extension StravaClient: ASWebAuthenticationPresentationContextProviding {
    
    
    // --- MODIFIED Authorization Flow ---
    
    /**
     Initiates the Strava OAuth flow (via app or web) and returns the authorization code and granted scopes upon successful user authorization and redirect.
     
     This method does NOT exchange the code for a token. That step must be handled separately using the returned code, typically by calling a secure backend endpoint.
     
     - Returns: A tuple containing the authorization `code` and the array of granted `scopes`.
     - Throws: Errors related to configuration, opening the Strava app/web view, user cancellation, or invalid redirect URIs.
     */
    @MainActor
    public func authorizeForCode() async throws -> (code: String, scopes: [Scope]) {
        checkConfiguration() // Ensure config is set
        
        let appAuthorizationUrl = Router.appAuthorizationUrl
        var redirectURL: URL? // Changed name for clarity
        
        print("StravaClient: Starting authorization flow...")
        
        // Try native app auth first
        if UIApplication.shared.canOpenURL(appAuthorizationUrl) {
            print("StravaClient: Attempting to open Strava app...")
            let didOpen = await UIApplication.shared.open(appAuthorizationUrl, options: [:])
            
            if !didOpen {
                print("StravaClient: Failed to open Strava app.")
                throw StravaClientError.openStravaFailed
            }
            
            // Wait for the app delegate/scene delegate to call handleAuthURL, which resumes this continuation
            print("StravaClient: Waiting for redirect URL from app delegate...")
            redirectURL = await withCheckedContinuation { continuation in
                self.authContinuation = continuation // Store the continuation
            }
            print("StravaClient: Received redirect URL via continuation: \(redirectURL?.absoluteString ?? "nil")")
        }
        // Fall back to web auth
        else {
            print("StravaClient: Strava app not installed or cannot be opened. Falling back to web authentication...")
            redirectURL = try await withCheckedThrowingContinuation { continuation in
                // Ensure redirectUri from config is valid
                guard let callbackScheme = config?.redirectUri.components(separatedBy: "://").first else {
                    print("StravaClient: Invalid redirectUri in config - cannot determine callback scheme.")
                    continuation.resume(throwing: StravaClientError.invalidRedirectURI)
                    return
                }
                
                print("StravaClient: Initiating ASWebAuthenticationSession with URL: \(Router.webAuthorizationUrl) and callback scheme: \(callbackScheme)")
                
                let webAuthenticationSession = ASWebAuthenticationSession(
                    url: Router.webAuthorizationUrl,
                    callbackURLScheme: callbackScheme // Use scheme from config's redirectUri
                ) { url, error in
                    if let error = error {
                        print("StravaClient: ASWebAuthenticationSession failed: \(error)")
                        // Handle cancellation specifically if needed
                        if (error as? ASWebAuthenticationSessionError)?.code == .canceledLogin {
                            continuation.resume(throwing: StravaClientError.runtimeError("User cancelled web authentication.")) // Or a specific cancellation error
                        } else {
                            continuation.resume(throwing: error)
                        }
                    } else if let url = url {
                        print("StravaClient: ASWebAuthenticationSession succeeded with URL: \(url)")
                        continuation.resume(returning: url)
                    } else {
                        print("StravaClient: ASWebAuthenticationSession returned no URL and no error.")
                        continuation.resume(throwing: StravaClientError.runtimeError("Web authentication returned an unexpected state."))
                    }
                }
                
                // Keep reference and set context provider
                self.authSession = webAuthenticationSession
                if #available(iOS 13.0, *) {
                    webAuthenticationSession.presentationContextProvider = self
                }
                webAuthenticationSession.start()
                print("StravaClient: ASWebAuthenticationSession started.")
            }
            print("StravaClient: Received redirect URL via web auth session: \(redirectURL?.absoluteString ?? "nil")")
        }
        
        // --- Process Redirect URL ---
        guard let finalURL = redirectURL else {
            // This should theoretically only happen if the continuation wasn't resumed (e.g., user cancel not handled cleanly)
            print("StravaClient: Error - Redirect URL is nil after auth flow.")
            throw StravaClientError.runtimeError("Authorization flow did not return a URL.")
        }
        
        // Validate the URL structure and extract code/scopes
        guard redirectURLIsValid(finalURL), // Use existing validation logic
              let params = finalURL.getQueryParameters(),
              let code = params["code"]
        else {
            // Check for explicit error parameter from Strava
            if let errorDesc = finalURL.getQueryParameters()?["error"] {
                print("StravaClient: Authorization failed with error from Strava: \(errorDesc)")
                throw StravaClientError.runtimeError("Authorization failed: \(errorDesc)")
            }
            // Otherwise, it's an invalid redirect or missing code
            print("StravaClient: Invalid redirect URI or missing code/scope/state.")
            throw StravaClientError.invalidRedirectURI // Or a more specific error
        }
        
        // Extract scopes
        let scopes = self.getScopes(from: finalURL) // Use existing helper
        
        print("StravaClient: Successfully extracted code: \(code.prefix(4))... and scopes: \(scopes.map { $0.rawValue })")
        
        // Return the code and scopes, NOT the token
        return (code: code, scopes: scopes)
    }
    
    @MainActor
    public func authorize() async throws -> StravaSwiftAuth {
        let appAuthorizationUrl = Router.appAuthorizationUrl
        
        var authURL: URL?
        
        // Try native app auth first
        if UIApplication.shared.canOpenURL(appAuthorizationUrl) {
            let didOpen = await UIApplication.shared.open(appAuthorizationUrl, options: [:])
            
            if !didOpen {
                throw StravaClientError.openStravaFailed
            }
            
            authURL = await withCheckedContinuation { continuation in
                self.authContinuation = continuation
            }
        }
        // Fall back to web auth
        else {
            authURL = try await withCheckedThrowingContinuation { continuation in
                let webAuthenticationSession = ASWebAuthenticationSession(
                    url: Router.webAuthorizationUrl,
                    callbackURLScheme: config?.redirectUri
                ) { url, error in
                    if let url = url, error == nil {
                        continuation.resume(returning: url)
                    } else if let error = error {
                        continuation.resume(throwing: error)
                    } else {
                        continuation.resume(
                            throwing: StravaClientError.runtimeError(
                                "Web authentication unknown error"))
                    }
                }
                
                webAuthenticationSession.presentationContextProvider = self
                webAuthenticationSession.start()
            }
        }
        
        guard let authURL = authURL, redirectURLIsValid(authURL) else {
            throw StravaClientError.invalidRedirectURI
        }
        
        // Get token and scopes
        guard let token = await getAccessToken(from: authURL) else {
            throw StravaClientError.tokenRetrievalFailed
        }
        
        let scopes = self.getScopes(from: authURL)
        
        // Create and store the auth state
        let auth = StravaSwiftAuth(token: token)
        return auth
    }
    
    var currentWindow: UIWindow? { return UIApplication.shared.keyWindow }
    var currentViewController: UIViewController? { return currentWindow?.rootViewController }
    
    /**
     Starts the Strava OAuth authorization. The authentication will use the Strava app be default if it is installed on the device. If the user does not have Strava installed, it will fallback on `SFAuthenticationSession` or `ASWebAuthenticationSession` depending on the iOS version used at runtime.
     */
    
    public func authorize(result: @escaping AuthorizationHandler) {
        let appAuthorizationUrl = Router.appAuthorizationUrl
        if UIApplication.shared.canOpenURL(appAuthorizationUrl) {
            currentAuthorizationHandler = result  // Stores the handler to be executed once `handleAuthorizationRedirect(url:)` is called
            if #available(iOS 10.0, *) {
                UIApplication.shared.open(appAuthorizationUrl, options: [:])
            } else {
                UIApplication.shared.openURL(appAuthorizationUrl)
            }
        } else {
            if #available(iOS 12.0, *) {
                let webAuthenticationSession = ASWebAuthenticationSession(
                    url: Router.webAuthorizationUrl,
                    callbackURLScheme: config?.redirectUri,
                    completionHandler: { (url, error) in
                        if let url = url, error == nil {
                            self.handleAuthorizationRedirect(url, result: result)
                        } else {
                            result(.failure(error!))
                        }
                    })
                authSession = webAuthenticationSession
                if #available(iOS 13.0, *) {
                    webAuthenticationSession.presentationContextProvider = self
                }
                webAuthenticationSession.start()
            } else {
                currentAuthorizationHandler = result  // Stores the handler to be executed once `handleAuthorizationRedirect(url:)` is called
                UIApplication.shared.open(Router.webAuthorizationUrl, options: [:])
            }
        }
    }
    
    /**
     Helper method to get the code from the redirection from Strava after the user has authorized the application (useful in AppDelegate)
     
     - Parameter url the url returned by Strava through the (ASWeb/SF)AuthenricationSession or application open options.
     - Returns: a boolean that indicates if this url is for Strava, has a code and can be handled properly
     **/
    
    public func redirectURLIsValid(_ url: URL) -> Bool {
        if let params = url.getQueryParameters(), params["code"] != nil, params["scope"] != nil,
           params["state"] == "ios"
        {
            return true
        } else {
            print("url is invalid:", url)
            return false
        }
    }
    
    //    public func redirectURLIsValid(_ url: URL) -> Bool {
    //        if let redirectUri = config?.redirectUri.components(separatedBy: "%3A%2F%2F").joined(separator: "://"), url.absoluteString.starts(with: redirectUri),
    //           let params = url.getQueryParameters(), params["code"] != nil, params["scope"] != nil, params["state"] == "ios" {
    //            return true
    //        }
    //        else {
    //            print("url is invalid:", url)
    //            return false
    //        }
    //    }
    
    public func handleAuthorizationRedirect(_ url: URL) -> Bool {
        
        if redirectURLIsValid(url) {
            
            self.handleAuthorizationRedirect(url) { result in
                if let currentAuthorizationHandler = self.currentAuthorizationHandler {
                    currentAuthorizationHandler(result)
                    self.currentAuthorizationHandler = nil
                }
            }
            return true
        } else {
            return false
        }
    }
    
    /**
     Helper method to get the code from the redirection from Strava after the user has authorized the application (useful in AppDelegate)
     
     - Parameter url the url returned by Strava through the (ASWeb/SF)AuthenricationSession or application open options.
     - Parameter result a closure to handle the OAuthToken
     **/
    private func handleAuthorizationRedirect(_ url: URL, result: @escaping AuthorizationHandler) {
        
        if let code = url.getQueryParameters()?["code"] {
            self.getAccessToken(code, result: result)
        } else {
            result(
                .failure(generateError(failureReason: "Invalid authorization code", response: nil)))
        }
    }
    
    /**
     Get an OAuth token from Strava
     
     - Parameter code: the code (string) returned from strava
     - Parameter result: a closure to handle the OAuthToken
     **/
    private func getAccessToken(_ code: String, result: @escaping AuthorizationHandler) {
        do {
            try oauthRequest(Router.token(code: code))?.responseStrava {
                [weak self] (response: DataResponse<OAuthToken>) in
                guard let self = self, let token = response.result.value else { return }
                //let token = response.result.value!
                self.config?.delegate.set(token)
                result(.success(token))
            }
        } catch let error as NSError {
            result(.failure(error))
        }
    }
    
    /**
     Refresh an OAuth token from Strava
     
     - Parameter refresh: the refresh token from Strava
     - Parameter result: a closure to handle the OAuthToken
     **/
    public func refreshAccessToken(_ refreshToken: String, result: @escaping AuthorizationHandler) {
        do {
            try oauthRequest(Router.refresh(refreshToken: refreshToken))?.responseStrava {
                [weak self] (response: DataResponse<OAuthToken>) in
                guard let self = self else { return }
                if let token = response.result.value {
                    self.config?.delegate.set(token)
                    result(.success(token))
                } else {
                    result(
                        .failure(self.generateError(failureReason: "No valid token", response: nil))
                    )
                }
            }
        } catch let error as NSError {
            result(.failure(error))
        }
    }
    
    // ASWebAuthenticationPresentationContextProviding
    
    //    @available(iOS 12.0, *)
    public func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor
    {
        return currentWindow ?? ASPresentationAnchor()
    }
}
#endif
