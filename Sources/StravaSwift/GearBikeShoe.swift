//
//  Gear.swift
//  StravaSwift
//
//  Created by Matthew on 15/11/2015.
//  Copyright © 2015 Matthew Clarkson. All rights reserved.
//

import Foundation
import SwiftyJSON

/**
 Gear represents equipment used during an activity. The object is returned in summary or detailed representations.
 **/
open class Gear: Strava, Codable {
    public let id: String?
    public let primary: Bool?
    public let nickname: String?
    public let description: String?
    public let resourceState: ResourceState?
    public let distance: Double?
    public let brandName: String?
    public let modelName: String?

    required public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decodeIfPresent(String.self, forKey: .id)
        primary = try container.decodeIfPresent(Bool.self, forKey: .primary)
        nickname = try container.decodeIfPresent(String.self, forKey: .nickname)
        description = try container.decodeIfPresent(String.self, forKey: .description)
        resourceState = try container.decodeIfPresent(ResourceState.self, forKey: .resourceState)
        distance = try container.decodeIfPresent(Double.self, forKey: .distance)
        brandName = try container.decodeIfPresent(String.self, forKey: .brandName)
        modelName = try container.decodeIfPresent(String.self, forKey: .modelName)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        try container.encode(primary, forKey: .primary)
        try container.encode(nickname, forKey: .nickname)
        try container.encode(description, forKey: .description)
        try container.encode(resourceState, forKey: .resourceState)
        try container.encode(distance, forKey: .distance)
        try container.encode(brandName, forKey: .brandName)
        try container.encode(modelName, forKey: .modelName)
    }

    required public init(_ json: JSON) {
        id = json["id"].string
        primary = json["primary"].bool
        nickname = json["nickname"].string
        description = json["description"].string
        resourceState = json["resource_state"].strava(ResourceState.self)
        distance = json["distance"].double
        brandName = json["brand_name"].string
        modelName = json["model_name"].string
    }

    private enum CodingKeys: String, CodingKey {
        case id, primary, nickname, description, resourceState, distance, brandName, modelName
    }
}


/**
  Shoe represents shoes worn on a run. The object is returned in summary or detailed representations.
 **/
public final class Shoe: Gear {}

/**
 Bike represents a... bike!  The object is returned in summary or detailed representations.
 **/
public final class Bike: Gear {
    
    public let frameType: FrameType?
    public let weight: Double?

    required public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        frameType = try container.decodeIfPresent(FrameType.self, forKey: .frameType)
        weight = try container.decodeIfPresent(Double.self, forKey: .weight)
        try super.init(from: decoder)
    }

    public override func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(frameType, forKey: .frameType)
        try container.encode(weight, forKey: .weight)
        try super.encode(to: encoder)
    }

    required public init(_ json: JSON) {
        frameType = json["frame_type"].strava(FrameType.self)
        weight = json["weight"].double
        super.init(json)
    }

    private enum CodingKeys: String, CodingKey {
        case frameType
        case weight
    }
}
