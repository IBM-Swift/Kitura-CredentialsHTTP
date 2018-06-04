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

import Foundation
import XCTest

import Kitura
import KituraNet
import Credentials

@testable import CredentialsHTTP

class TestTypeSafeBasic : XCTestCase {
    
    static var allTests : [(String, (TestTypeSafeBasic) -> () throws -> Void)] {
        return [
            ("testTypeSafeNoCredentials", testTypeSafeNoCredentials),
        ]
    }
    
    override func setUp() {
        doSetUp()
    }
    
    override func tearDown() {
        doTearDown()
    }
    
    let host = "127.0.0.1"
    
    let router = TestTypeSafeBasic.setupTypeSafeRouter()
    
    func testTypeSafeNoCredentials() {
        performServerTest(router: router) { expectation in
            self.performRequest(method: "get", host: self.host, path: "/private/typesafebasic", callback: {response in
                XCTAssertNotNil(response, "ERROR!!! ClientRequest response object was nil")
                XCTAssertEqual(response?.statusCode, HTTPStatusCode.unauthorized, "HTTP Status code was \(String(describing: response?.statusCode))")
                XCTAssertEqual(response?.headers["WWW-Authenticate"]?.first, "Basic realm=\"test\"")
                expectation.fulfill()
            })
        }
    }
    
    func testTypeSafeBadCredentials() {
        
        performServerTest(router: router) { expectation in
            self.performRequest(method: "get", path:"/private/typesafebasic", callback: {response in
                XCTAssertNotNil(response, "ERROR!!! ClientRequest response object was nil")
                XCTAssertEqual(response?.statusCode, HTTPStatusCode.unauthorized, "HTTP Status code was \(String(describing: response?.statusCode))")
                XCTAssertEqual(response?.headers["WWW-Authenticate"]?.first, "Basic realm=\"test\"")
                expectation.fulfill()
            }, headers: ["Authorization" : "Basic QWxhZGRpbjpPcGVuU2VzYW1l"])
        }
        
        performServerTest(router: router) { expectation in
            self.performRequest(method: "get", path:"/private/typesafebasic", callback: {response in
                XCTAssertNotNil(response, "ERROR!!! ClientRequest response object was nil")
                XCTAssertEqual(response?.statusCode, HTTPStatusCode.unauthorized, "HTTP Status code was \(String(describing: response?.statusCode))")
                XCTAssertEqual(response?.headers["WWW-Authenticate"]?.first, "Basic realm=\"test\"")
                expectation.fulfill()
            }, headers: ["Authorization" : "Basic"])
        }
    }
    
    func testTypeSafeBasic() {

        performServerTest(router: router) { expectation in
            self.performRequest(method: "get", path:"/private/typesafebasic", callback: {response in
                XCTAssertNotNil(response, "ERROR!!! ClientRequest response object was nil")
                XCTAssertEqual(response?.statusCode, HTTPStatusCode.OK, "HTTP Status code was \(String(describing: response?.statusCode))")
                do {
                    let body = try response?.readString()
                    XCTAssertEqual(body,"{\"name\":\"Mary\",\"provider\":\"HTTPBasic\"}")
                }
                catch{
                    XCTFail("No response body")
                }
                expectation.fulfill()
            }, headers: ["Authorization" : "Basic TWFyeTpxd2VyYXNkZg=="])
        }
    }
    
    static func setupTypeSafeRouter() -> Router {
        let router = Router()
        
        router.get("/private/typesafebasic") { (authedUser: TestHTTPBasic, respondWith: (User?, RequestError?) -> Void) in
            let user = User(name: authedUser.id, provider: authedUser.provider)
            respondWith(user, nil)
        }
        
        return router
    }
    
    public struct TestHTTPBasic: TypeSafeHTTPBasic {
        
        public let id: String
        
        static let users = ["John" : "12345", "Mary" : "qwerasdf"]
        
        public static let realm = "test"
        
        public static var verifyPassword: ((String, String, @escaping (TestHTTPBasic?) -> Void) -> Void) =
        { userId, password, callback in
            if let storedPassword = users[userId], storedPassword == password {
                callback(TestHTTPBasic(id: userId))
            } else {
                callback(nil)
            }
        }
    }
    
    struct User: Codable {
        let name: String
        let provider: String
    }
}
