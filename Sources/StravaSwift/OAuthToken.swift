//
//  OAuthToken.swift
//  StravaSwift
//
//  Created by Matthew on 11/11/2015.
//  Copyright © 2015 Matthew Clarkson. All rights reserved.
//

import Foundation
import SwiftyJSON

/**
OAuthToken which is required for requesting Strava resources
 **/
public struct OAuthToken: Strava, Codable {

    /** The access token **/
    public let accessToken: String?

    /** The refresh token **/
    public let refreshToken: String?

    /** Expiry for the token in seconds since the epoch **/
    public let expiresAt : Date?

    /** The athlete **/
    public let athlete: Athlete?

    /**
     Initializers

     - Parameter json: A SwiftyJSON object
     **/
    public init(_ json: JSON) {
        accessToken = json["access_token"].string
        refreshToken = json["refresh_token"].string
        if let intExpiry = json["expires_at"].int {
            expiresAt = Date(timeIntervalSince1970: TimeInterval(intExpiry))
        }
        else {
            expiresAt = nil
        }
        athlete = Athlete(json["athlete"])
    }

    public init(access: String?, refresh: String?, expiry: Date?) {
        self.accessToken = access
        self.refreshToken = refresh
        self.expiresAt = expiry
        self.athlete = nil
    }
}
