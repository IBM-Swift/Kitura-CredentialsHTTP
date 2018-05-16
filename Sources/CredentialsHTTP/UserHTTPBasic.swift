/**
 * Copyright IBM Corporation 2016
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

public final class UserHTTPBasic : TypedCredentialsPluginProtocol {
    
    public static var options: [String : Any] = [:]
    public static var realm: String = "User"
    
    public static var name: String = "HTTP Basic"
    
    public static var usersCache: NSCache<NSString, BaseCacheElement>? = nil
    
    public static var redirecting: Bool = false
    
    public static var verifyPassword: ((String, String, @escaping (UserHTTPBasic?) -> Void) -> Void)? = nil
    
    public static func describe() -> String {
        return "HTTPBasic"
    }
    
    public let id: String
    public let provider: String
    
    required public init(id: String, provider: String) {
        self.id = id
        self.provider = provider
    }
    
    /// Authenticate incoming request using HTTP Basic authentication.
    ///
    /// - Parameter request: The `RouterRequest` object used to get information
    ///                     about the request.
    /// - Parameter response: The `RouterResponse` object used to respond to the
    ///                       request.
    /// - Parameter options: The dictionary of plugin specific options.
    /// - Parameter onSuccess: The closure to invoke in the case of successful authentication.
    /// - Parameter onFailure: The closure to invoke in the case of an authentication failure.
    /// - Parameter onPass: The closure to invoke when the plugin doesn't recognize the
    ///                     authentication data in the request.
    /// - Parameter inProgress: The closure to invoke to cause a redirect to the login page in the
    ///                     case of redirecting authentication.
    public static func authenticate(request: RouterRequest, response: RouterResponse, onSuccess: @escaping (UserHTTPBasic) -> Void, onFailure: @escaping (HTTPStatusCode?, [String : String]?) -> Void, onPass: @escaping (HTTPStatusCode?, [String : String]?) -> Void, inProgress: @escaping () -> Void) {
        
        var authorization : String
        if let user = request.urlURL.user, let password = request.urlURL.password {
            authorization = user + ":" + password
        }
        else {
            let options = Data.Base64DecodingOptions(rawValue: 0)
            
            guard let authorizationHeader = request.headers["Authorization"]  else {
                // TODO: this should be onPass, changed for demo
                onFailure(.unauthorized, ["WWW-Authenticate" : "Basic realm=\"" + realm + "\""])
                return
            }
            
            let authorizationHeaderComponents = authorizationHeader.components(separatedBy: " ")
            guard authorizationHeaderComponents.count == 2,
                authorizationHeaderComponents[0] == "Basic",
                let decodedData = Data(base64Encoded: authorizationHeaderComponents[1], options: options),
                let userAuthorization = String(data: decodedData, encoding: .utf8) else {
                    // TODO: this should be onPass, changed for demo
                    onFailure(.unauthorized, ["WWW-Authenticate" : "Basic realm=\"" + realm + "\""])
                    return
            }
            
            authorization = userAuthorization as String
        }
        
        let credentials = authorization.components(separatedBy: ":")
        guard credentials.count >= 2 else {
            onFailure(.badRequest, nil)
            return
        }
        
        let userid = credentials[0]
        let password = credentials[1]
        
        if let verifyPassword = verifyPassword {
            verifyPassword(userid, password) { selfInstance in
                if let selfInstance = selfInstance {
                    onSuccess(selfInstance)
                }
                else {
                    onFailure(.unauthorized, ["WWW-Authenticate" : "Basic realm=\"" + self.realm + "\""])
                }
            }
        }
        else {
            // either verifyPassword or userProfileLoader must be valid
            onFailure(.internalServerError, ["WWW-Authenticate" : "Internal server error"])
        }
    }
}
