package wxpay

type WxConfig struct {
	AppId          string
	AppKey         string
	MchId          string
	NotifyUrl      string
	PlaceOrderUrl  string
	QueryOrderUrl  string
	CloseOrderUrl  string
	RefundOrderUrl string
	WxCertPath     string
	WxKeyPath      string
	WxCAPath       string
	TradeType      string
}
