import XCTest
@testable import SwiftRTNetlink

final class SwiftRTNetlinkTests: XCTestCase {
    func testNetworkInterfaceCheck() throws {
    	let interfaces = try RTNetlink.getInterfaces()
    }
}
