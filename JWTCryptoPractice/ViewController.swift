//
//  ViewController.swift
//  JWTCryptoPractice
//
//  Created by sdev-mac on 2021/02/01.
//

import UIKit

class ViewController: UIViewController {

    @IBOutlet weak var tvHeader: UITextView!
    @IBOutlet weak var tvPayLoad: UITextView!
    @IBOutlet weak var tvVerifySignature: UITextView!
    @IBOutlet weak var tvEncryptedResult: UITextView!
    
    @IBOutlet weak var tfScretKey: UITextField!
    
    @IBOutlet weak var tvExtractedHeader: UITextView!
    @IBOutlet weak var tvExtractedPayLoad: UITextView!
    
    
    var crypto: Crypto!
    
    var hmacScreetKey = "test"
    
    override func viewDidLoad() {
        super.viewDidLoad()
   
        crypto = Crypto()
        
        encrypt()   //암호화
    }

    //버튼 클릭
    @IBAction func encryptButtonTouched(_ sender: Any) {
        
        self.view.endEditing(true)
        encrypt()
        
    }
    
    
    //암호화 시작
    func encrypt() {
        
        if tfScretKey.text != "" {
            hmacScreetKey = tfScretKey.text!
        }
        
        //Header
        let headerText = tvHeader.text.removeSpaceFromJsonString() //JSON 형태 값들 사이 공백 제거
        
        guard let base64HeaderString = crypto.base64StringFromDataString(dataString: headerText!) else { return }
        
        let headerString = base64HeaderString.removePaddingFromBase64()   //패딩 존재시 제거
        
        
        //Playload
        let payloadText = tvPayLoad.text.removeSpaceFromJsonString() //JSON 형태 값들 사이 공백 제거
        
        guard let base64PayloadString = crypto.base64StringFromDataString(dataString: payloadText!) else { return }

        let payloadString = base64PayloadString.removePaddingFromBase64()   //패딩 존재시 제거

        let dataString = headerString + "." + payloadString
                
        var signature = dataString.hmacBase64Encrypt(algorithm: .SHA256, key: hmacScreetKey)
        
        if signature.contains("/") {
            signature = signature.replacingOccurrences(of: "/", with: "_")
        }
        
        signature = signature.removePaddingFromBase64()   //패딩 존재시 제거

        
        self.tvVerifySignature.text = signature
        
        let JWTString = headerString + "." + payloadString + "." + signature
        
        self.tvEncryptedResult.text = JWTString
        
        
        //추출
        
        let encodedHeader = JWTString.components(separatedBy: ".")  //문자열 기준으로 자름
        
        let encodedHeader2 = JWTString.split(separator: ".")    //문자 기준으로 자름
        
        
        print(encodedHeader2)
        
        tvExtractedHeader.text = crypto.base64StringToString(base64String: encodedHeader[0])
        
        let payload = crypto.base64StringToString(base64String: encodedHeader[1])
        
        tvExtractedPayLoad.text = payload
    }
}

