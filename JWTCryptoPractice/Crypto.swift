//
//  CryptoString.swift
//  PicaCryptoPractice
//
//  Created by sdev-mac on 2021/01/25.
//

import Foundation
import CommonCrypto
import CryptoKit
import CryptoTokenKit

class Crypto {
    
    private static let ALGORITHM: String = "hmacSHA256";
    
    func convertSHA256ToString(data: Data) -> String {

        if #available(iOS 13.0, *) {
            
            let hashed = SHA256.hash(data: data)
            
            print("result data = \(hashed.description)")
            
            return hashed.description

        } else {
            
            let hashed = self.sha256ToNSData(data: data)
            
            let hex = self.hexStringFromNSData(input: hashed)
            
            print("hashed = \(hex.description)")
            
            return hex.description
        }
    }
    
    func sha256ToNSData(data: Data) -> NSData {
        
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes {
            _ = CC_SHA256($0, CC_LONG(data.count), &hash)
        }
        
        let res = NSData(bytes: hash, length: Int(CC_SHA256_DIGEST_LENGTH))
        
        return res
    }
    
    func hexStringFromNSData(input: NSData) -> String {
        var bytes = [UInt8](repeating: 0, count: input.length)
        input.getBytes(&bytes, length: input.length)

        var hexString = ""
        for byte in bytes {
            hexString += String(format:"%02x", UInt8(byte))
        }

        return hexString
    }
    

    func base64StringFromDataString(dataString: String) -> String? {

        let utf8str = dataString.data(using: .utf8)
        
        guard  let base64EncodedString = utf8str?.base64EncodedString(options: Data.Base64EncodingOptions(rawValue: 0)) else { return nil }
        
        return base64EncodedString
    }
    
    func base64StringToString(base64String: String) -> String? {
        
        var encodedBase64String = base64String
        guard let utf8str = encodedBase64String.data(using: .utf8)?.count else { return "" }

        let count = utf8str % 3
        
        if count == 1 {

            encodedBase64String = encodedBase64String + "=" //공백 추가 해줌
            
        } else if count == 2 {
            
            encodedBase64String = base64String + "=="   //공백 추가 해줌
        }
    
        guard let decodedData = Data(base64Encoded: encodedBase64String) else { return nil }
        
        print(decodedData.count)
        
        let decodedString = String(data: decodedData, encoding: .utf8)!
        
        return decodedString
    }
}

enum CryptoAlgorithm {
    case MD5, SHA1, SHA224, SHA256, SHA384, SHA512

    var HMACAlgorithm: CCHmacAlgorithm {
        var result: Int = 0
        switch self {
        case .MD5:      result = kCCHmacAlgMD5
        case .SHA1:     result = kCCHmacAlgSHA1
        case .SHA224:   result = kCCHmacAlgSHA224
        case .SHA256:   result = kCCHmacAlgSHA256
        case .SHA384:   result = kCCHmacAlgSHA384
        case .SHA512:   result = kCCHmacAlgSHA512
        }
        return CCHmacAlgorithm(result)
    }

    var digestLength: Int {
        var result: Int32 = 0
        switch self {
        case .MD5:      result = CC_MD5_DIGEST_LENGTH
        case .SHA1:     result = CC_SHA1_DIGEST_LENGTH
        case .SHA224:   result = CC_SHA224_DIGEST_LENGTH
        case .SHA256:   result = CC_SHA256_DIGEST_LENGTH
        case .SHA384:   result = CC_SHA384_DIGEST_LENGTH
        case .SHA512:   result = CC_SHA512_DIGEST_LENGTH
        }
        return Int(result)
    }
}

extension String {
    
    //Encrypt
    func hmacEncrypt(algorithm: CryptoAlgorithm, key: String) -> String {
        let str = self.cString(using: String.Encoding.utf8)
        let strLen = Int(self.lengthOfBytes(using: String.Encoding.utf8))
        let digestLen = algorithm.digestLength
        let result = UnsafeMutablePointer<CUnsignedChar>.allocate(capacity: digestLen)
        let keyStr = key.cString(using: String.Encoding.utf8)
        let keyLen = Int(key.lengthOfBytes(using: String.Encoding.utf8))

        CCHmac(algorithm.HMACAlgorithm, keyStr!, keyLen, str!, strLen, result)

        let digest = stringFromResult(result: result, length: digestLen)

        result.deallocate()

        return digest
    }
    
    //BASE64 Encrypt
    func hmacBase64Encrypt(algorithm: CryptoAlgorithm, key: String) -> String {
           let cKey = key.cString(using: String.Encoding.utf8)
           let cData = self.cString(using: String.Encoding.utf8)
           let result = UnsafeMutablePointer<CUnsignedChar>.allocate(capacity: algorithm.digestLength)
            CCHmac(algorithm.HMACAlgorithm, cKey!, strlen(cKey!), cData!, strlen(cData!), result)
           let hmacData:NSData = NSData(bytes: result, length: (algorithm.digestLength))
           let hmacBase64 = hmacData.base64EncodedString()
           return String(hmacBase64)
       }

    //Decrypt
    func hmacBase64Decrypt(algorithm: CryptoAlgorithm, key: String) {
        
        let cKey = key.cString(using: String.Encoding.utf8)
        let cData = self.cString(using: String.Encoding.utf8)
    }
    
    private func stringFromResult(result: UnsafeMutablePointer<CUnsignedChar>, length: Int) -> String {
        let hash = NSMutableString()
        for i in 0..<length {
            hash.appendFormat("%02x", result[i])
        }
        return String(hash).lowercased()
    }
    
    //JSON String 문자열의 값사이 공백 제거( ex- "key" :    "value )
    func removeSpaceFromJsonString() -> String? {
        let string = self.components(separatedBy:"\"")
            .enumerated()
            .map{ ($0 % 2 == 1) ? $1 : $1.replacingOccurrences(of: " ", with: "") }
            .joined(separator: "\"")
        
        return string.components(separatedBy:"\"")
            .enumerated()
            .map{ ($0 % 2 == 1) ? $1 : $1.replacingOccurrences(of: "\n", with: "") }
            .joined(separator: "\"")
    }
    
    //base64 문자열의 끝 패딩 제거 (==  또는 =)
    func removePaddingFromBase64() -> String {
        if self.hasSuffix("==") {
            return self.replacingOccurrences(of: "==", with: "")
        } else if self.hasSuffix("=") {
            return self.replacingOccurrences(of: "=", with: "")
        }
        return self
    }
}
