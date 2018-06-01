/**
 * Copyright IBM Corporation 2018
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 **/

import Kitura
import KituraNet
import Credentials

import Foundation

public protocol TypeSafeHTTPBasic : TypeSafeCredentials {
    
    /// The unique identifier for the authentication providers
    var id: String { get }
    
    /// The name of the authentication provider (defaults to "Facebook")
    var provider: String { get }
    
    /// The realm for which these credentials are valid (defaults to "User")
    static var realm: String { get }
    
    // The closure which takes a username and password and returns a TypeSafeHTTPBasic instance on success or nil on failure.
    static var verifyPassword: ((String, String, @escaping (TypeSafeHTTPBasic?) -> Void) -> Void) { get }
    
    /// Authenticate incoming request using HTTP Basic authentication.
    ///
    /// - Parameter request: The `RouterRequest` object used to get information
    ///                     about the request.
    /// - Parameter response: The `RouterResponse` object used to respond to the
    ///                       request.
    /// - Parameter onSuccess: The closure to invoke in the case of successful authentication.
    /// - Parameter onFailure: The closure to invoke in the case of an authentication failure.
    /// - Parameter onPass: The closure to invoke when the plugin doesn't recognize the
    ///                     authentication data in the request.
    static func authenticate(request: RouterRequest, response: RouterResponse, onSuccess: @escaping (TypeSafeHTTPBasic) -> Void, onFailure: @escaping (HTTPStatusCode?, [String : String]?) -> Void, onPass: @escaping (HTTPStatusCode?, [String : String]?) -> Void, inProgress: @escaping () -> Void)
}

extension TypeSafeHTTPBasic {
    
    public var provider: String {
        return "Facebook"
    }
    
    public var realm: String {
        return "User"
    }
    
    /// Authenticate incoming request using HTTP Basic authentication.
    ///
    /// - Parameter request: The `RouterRequest` object used to get information
    ///                     about the request.
    /// - Parameter response: The `RouterResponse` object used to respond to the
    ///                       request.
    /// - Parameter onSuccess: The closure to invoke in the case of successful authentication.
    /// - Parameter onFailure: The closure to invoke in the case of an authentication failure.
    /// - Parameter onPass: The closure to invoke when the plugin doesn't recognize the
    ///                     authentication data in the request.
    public static func authenticate(request: RouterRequest, response: RouterResponse, onSuccess: @escaping (TypeSafeHTTPBasic) -> Void, onFailure: @escaping (HTTPStatusCode?, [String : String]?) -> Void, onPass: @escaping (HTTPStatusCode?, [String : String]?) -> Void, inProgress: @escaping () -> Void) {
        
        let userid: String
        let password: String
        if let requestUser = request.urlURL.user, let requestPassword = request.urlURL.password {
            userid = requestUser
            password = requestPassword
        }
        else {
            guard let authorizationHeader = request.headers["Authorization"]  else {
                return onPass(.unauthorized, ["WWW-Authenticate" : "Basic realm=\"" + realm + "\""])
            }
            
            let authorizationHeaderComponents = authorizationHeader.components(separatedBy: " ")
            guard authorizationHeaderComponents.count == 2,
                authorizationHeaderComponents[0] == "Basic",
                let decodedData = Data(base64Encoded: authorizationHeaderComponents[1], options: Data.Base64DecodingOptions(rawValue: 0)),
                let userAuthorization = String(data: decodedData, encoding: .utf8) else {
                    return onPass(.unauthorized, ["WWW-Authenticate" : "Basic realm=\"" + realm + "\""])
            }
            let credentials = userAuthorization.components(separatedBy: ":")
            guard credentials.count >= 2 else {
                onFailure(.badRequest, nil)
                return
            }
            userid = credentials[0]
            password = credentials[1]
        }
        
        verifyPassword(userid, password) { selfInstance in
            if let selfInstance = selfInstance {
                onSuccess(selfInstance)
            }
            else {
                onFailure(.unauthorized, ["WWW-Authenticate" : "Basic realm=\"" + self.realm + "\""])
            }
        }
    }
}
