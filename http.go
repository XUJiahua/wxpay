package wxpay

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
)

const (
	RETURN_CODE_SUCCESS = "SUCCESS"
	RETURN_CODE_FAIL    = "FAIL"
)

const (
	RESULT_CODE_SUCCESS = "SUCCESS"
	RESULT_CODE_FAIL    = "FAIL"
)

// AppTrans is abstact of Transaction handler. With AppTrans, we can get prepay id
type AppTrans struct {
	Config *WxConfig
}

var _tlsConfig *tls.Config

func (this *AppTrans) getTLSConfig() (*tls.Config, error) {
	if _tlsConfig != nil {
		return _tlsConfig, nil
	}

	// load cert
	cert, err := tls.LoadX509KeyPair(this.Config.WxCertPath, this.Config.WxKeyPath)
	if err != nil {
		return nil, err
	}

	// load root ca
	caData, err := ioutil.ReadFile(this.Config.WxCAPath)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caData)

	_tlsConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
	}
	return _tlsConfig, nil
}

// Initialized the AppTrans with specific config
func NewAppTrans(cfg *WxConfig) (*AppTrans, error) {
	if cfg.AppId == "" ||
		cfg.MchId == "" ||
		cfg.AppKey == "" ||
		cfg.NotifyUrl == "" ||
		cfg.QueryOrderUrl == "" ||
		cfg.PlaceOrderUrl == "" ||
		cfg.CloseOrderUrl == "" ||
		cfg.TradeType == "" {
		return &AppTrans{Config: cfg}, errors.New("config field canot empty string")
	}

	return &AppTrans{Config: cfg}, nil
}

// Close order
func (this *AppTrans) Close(orderId string) error {
	odrInXml := this.signedCloseOrderRequestXmlString(orderId)
	resp, err := doHttpPost(this.Config.CloseOrderUrl, []byte(odrInXml))
	if err != nil {
		return err
	}

	println(string(resp))

	placeOrderResult, err := ParsePlaceOrderResult(resp)
	if err != nil {
		return err
	}

	if placeOrderResult.ReturnCode != RETURN_CODE_SUCCESS {
		return fmt.Errorf("return code:%s, return desc:%s", placeOrderResult.ReturnCode, placeOrderResult.ReturnMsg)
	}

	//Verify the sign of response
	resultInMap := placeOrderResult.ToMap()
	wantSign := Sign(resultInMap, this.Config.AppKey)
	gotSign := resultInMap["sign"]
	if wantSign != gotSign {
		return fmt.Errorf("sign not match, want:%s, got:%s", wantSign, gotSign)
	}

	if placeOrderResult.ResultCode != RESULT_CODE_SUCCESS {
		return fmt.Errorf("resutl code:%s, result desc:%s", placeOrderResult.ErrCode, placeOrderResult.ErrCodeDesc)
	}

	return nil
}

// Refund
func (this *AppTrans) Refund(orderId string, amount float64, refundOrderId string, refundAmount float64) error {
	odrInXml := this.signedRefundOrderRequestXmlString(orderId, fmt.Sprintf("%.0f", amount), refundOrderId, fmt.Sprintf("%.0f", refundAmount))
	tlsConfig, err := this.getTLSConfig()
	if err != nil {
		return err
	}

	resp, err := doHttpPostWithCert(this.Config.RefundOrderUrl, []byte(odrInXml), tlsConfig)
	if err != nil {
		return err
	}

	placeOrderResult, err := ParsePlaceOrderResult(resp)
	if err != nil {
		return err
	}

	if placeOrderResult.ReturnCode != RETURN_CODE_SUCCESS {
		return fmt.Errorf("return code:%s, return desc:%s", placeOrderResult.ReturnCode, placeOrderResult.ReturnMsg)
	}

	//Verify the sign of response
	resultInMap := placeOrderResult.ToMap()
	wantSign := Sign(resultInMap, this.Config.AppKey)
	gotSign := resultInMap["sign"]
	if wantSign != gotSign {
		return fmt.Errorf("sign not match, want:%s, got:%s", wantSign, gotSign)
	}

	if placeOrderResult.ResultCode != RESULT_CODE_SUCCESS {
		return fmt.Errorf("resutl code:%s, result desc:%s", placeOrderResult.ErrCode, placeOrderResult.ErrCodeDesc)
	}

	return nil
}

// Submit the order to weixin pay and return the prepay id if success,
// Prepay id is used for app to start a payment
// If fail, error is not nil, check error for more information
func (this *AppTrans) Submit(orderId string, amount float64, desc string, clientIp string, openId string) (string, error) {

	odrInXml := this.signedOrderRequestXmlString(orderId, fmt.Sprintf("%.0f", amount), desc, clientIp, openId)
	resp, err := doHttpPost(this.Config.PlaceOrderUrl, []byte(odrInXml))
	if err != nil {
		return "", err
	}

	placeOrderResult, err := ParsePlaceOrderResult(resp)
	if err != nil {
		return "", err
	}

	if placeOrderResult.ReturnCode != RETURN_CODE_SUCCESS {
		return "", fmt.Errorf("return code:%s, return desc:%s", placeOrderResult.ReturnCode, placeOrderResult.ReturnMsg)
	}

	//Verify the sign of response
	resultInMap := placeOrderResult.ToMap()
	wantSign := Sign(resultInMap, this.Config.AppKey)
	gotSign := resultInMap["sign"]
	if wantSign != gotSign {
		return "", fmt.Errorf("sign not match, want:%s, got:%s", wantSign, gotSign)
	}

	if placeOrderResult.ResultCode != RESULT_CODE_SUCCESS {
		return "", fmt.Errorf("resutl code:%s, result desc:%s", placeOrderResult.ErrCode, placeOrderResult.ErrCodeDesc)
	}

	return placeOrderResult.PrepayId, nil
}

func (this *AppTrans) newQueryXml(transId string) string {
	param := make(map[string]string)
	param["appid"] = this.Config.AppId
	param["mch_id"] = this.Config.MchId
	//param["transaction_id"] = transId
	param["out_trade_no"] = transId
	param["nonce_str"] = NewNonceString()

	sign := Sign(param, this.Config.AppKey)
	param["sign"] = sign

	return ToXmlString(param)
}

// Query the order from weixin pay server by transaction id of weixin pay
func (this *AppTrans) Query(transId string) (*QueryOrderResult, error) {
	queryOrderResult := QueryOrderResult{}

	queryXml := this.newQueryXml(transId)

	resp, err := doHttpPost(this.Config.QueryOrderUrl, []byte(queryXml))
	if err != nil {
		return nil, err
	}

	queryOrderResult, err = ParseQueryOrderResult(resp)
	if err != nil {
		return nil, err
	}

	if queryOrderResult.ReturnCode != RETURN_CODE_SUCCESS {
		return nil, fmt.Errorf("return code:%s, return desc:%s", queryOrderResult.ReturnCode, queryOrderResult.ReturnMsg)
	}

	//verity sign of response
	resultInMap := queryOrderResult.ToMap()
	wantSign := Sign(resultInMap, this.Config.AppKey)
	gotSign := resultInMap["sign"]
	if wantSign != gotSign {
		return nil, fmt.Errorf("sign not match, want:%s, got:%s", wantSign, gotSign)
	}

	if queryOrderResult.ResultCode != RESULT_CODE_SUCCESS {
		return &queryOrderResult, fmt.Errorf("resutl code:%s, result desc:%s", queryOrderResult.ErrCode, queryOrderResult.ErrCodeDesc)
	}

	return &queryOrderResult, nil
}

// NewPaymentRequest build the payment request structure for app to start a payment.
// Return stuct of PaymentRequest, please refer to http://pay.weixin.qq.com/wiki/doc/api/app.php?chapter=9_12&index=2
func (this *AppTrans) NewPaymentRequest(prepayId string) PaymentRequest {
	noncestr := NewNonceString()
	timestamp := NewTimestampString()

	param := make(map[string]string)
	param["appId"] = this.Config.AppId
	//param["partnerid"] = this.Config.MchId
	//param["prepayid"] = prepayId
	param["package"] = "prepay_id=" + prepayId
	param["nonceStr"] = noncestr
	param["timeStamp"] = timestamp
	param["signType"] = "MD5"

	sign := Sign(param, this.Config.AppKey)

	payRequest := PaymentRequest{
		AppId: param["appId"],
		//PartnerId: this.Config.MchId,
		//PrepayId:  prepayId,
		Package:   param["package"],
		NonceStr:  param["nonceStr"],
		Timestamp: param["timeStamp"],
		SignType:  param["signType"],
		Sign:      sign,
	}

	return payRequest
}

func (this *AppTrans) newOrderRequest(orderId, amount, desc, clientIp, openId string) map[string]string {
	param := make(map[string]string)
	param["appid"] = this.Config.AppId
	param["attach"] = "透传字段" //optional
	param["body"] = desc
	param["mch_id"] = this.Config.MchId
	param["nonce_str"] = NewNonceString()
	param["notify_url"] = this.Config.NotifyUrl
	param["out_trade_no"] = orderId
	param["spbill_create_ip"] = clientIp
	param["total_fee"] = amount
	param["trade_type"] = this.Config.TradeType
	// JSAPI需要传openId
	if openId != "" {
		param["openid"] = openId
	}

	return param
}

func (this *AppTrans) newRefundOrderRequest(orderId, amount, refundOrderId, refundAmount string) map[string]string {
	param := make(map[string]string)
	param["appid"] = this.Config.AppId
	param["mch_id"] = this.Config.MchId
	param["nonce_str"] = NewNonceString()
	param["notify_url"] = this.Config.NotifyUrl
	param["out_trade_no"] = orderId
	param["out_refund_no"] = refundOrderId
	param["total_fee"] = amount
	param["refund_fee"] = refundAmount

	return param
}

func (this *AppTrans) newCloseOrderRequest(orderId string) map[string]string {
	param := make(map[string]string)
	param["appid"] = this.Config.AppId
	param["mch_id"] = this.Config.MchId
	param["nonce_str"] = NewNonceString()
	param["out_trade_no"] = orderId

	return param
}

func (this *AppTrans) signedCloseOrderRequestXmlString(orderId string) string {
	order := this.newCloseOrderRequest(orderId)
	sign := Sign(order, this.Config.AppKey)

	order["sign"] = sign

	return ToXmlString(order)
}

func (this *AppTrans) signedOrderRequestXmlString(orderId, amount, desc, clientIp, openId string) string {
	order := this.newOrderRequest(orderId, amount, desc, clientIp, openId)
	sign := Sign(order, this.Config.AppKey)

	order["sign"] = sign

	return ToXmlString(order)
}

func (this *AppTrans) signedRefundOrderRequestXmlString(orderId, amount, refundOrderId, refundAmount string) string {
	order := this.newRefundOrderRequest(orderId, amount, refundOrderId, refundAmount)
	sign := Sign(order, this.Config.AppKey)

	order["sign"] = sign

	return ToXmlString(order)
}

// doRequest post the order in xml format with a sign
func doHttpPost(targetUrl string, body []byte) ([]byte, error) {
	req, err := http.NewRequest("POST", targetUrl, bytes.NewBuffer([]byte(body)))
	if err != nil {
		return []byte(""), err
	}
	req.Header.Add("Content-type", "application/x-www-form-urlencoded;charset=UTF-8")

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
	}

	client := &http.Client{Transport: tr}

	resp, err := client.Do(req)
	if err != nil {
		return []byte(""), err
	}

	defer resp.Body.Close()
	respData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return []byte(""), err
	}

	return respData, nil
}

// doRequest post the order in xml format with a sign
func doHttpPostWithCert(targetUrl string, body []byte, tlsConfig *tls.Config) ([]byte, error) {
	req, err := http.NewRequest("POST", targetUrl, bytes.NewBuffer([]byte(body)))
	if err != nil {
		return []byte(""), err
	}
	req.Header.Add("Content-type", "application/x-www-form-urlencoded;charset=UTF-8")

	tr := &http.Transport{
		TLSClientConfig: tlsConfig,
	}
	client := &http.Client{Transport: tr}

	resp, err := client.Do(req)
	if err != nil {
		return []byte(""), err
	}

	defer resp.Body.Close()
	respData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return []byte(""), err
	}

	return respData, nil
}
