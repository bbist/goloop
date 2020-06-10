package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/icon-project/goloop/server/jsonrpc"
)

type JsonRpcClient struct {
	hc           *http.Client
	Endpoint     string
	CustomHeader map[string]string
}

type Response struct {
	Version string          `json:"jsonrpc"`
	Result  json.RawMessage `json:"result"`
	Error   *jsonrpc.Error  `json:"error,omitempty"`
	ID      interface{}     `json:"id"`
}

func NewJsonRpcClient(hc *http.Client, endpoint string) *JsonRpcClient {
	return &JsonRpcClient{hc: hc, Endpoint: endpoint, CustomHeader: make(map[string]string)}
}

func (c *JsonRpcClient) _do(req *http.Request) (resp *http.Response, err error) {
	resp, err = c.hc.Do(req)
	if err != nil {
		return
	}
	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("http-status(%s) is not StatusOK", resp.Status)
		return
	}
	return
}

func (c *JsonRpcClient) Do(method string, reqPtr, respPtr interface{}) (jrResp *Response, err error) {
	jrReq := &jsonrpc.Request{
		ID:      time.Now().UnixNano() / int64(time.Millisecond),
		Version: jsonrpc.Version,
		Method:  method,
	}
	if reqPtr != nil {
		b, mErr := json.Marshal(reqPtr)
		if mErr != nil {
			err = mErr
			return
		}
		jrReq.Params = json.RawMessage(b)
	}
	reqB, err := json.Marshal(jrReq)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", c.Endpoint, bytes.NewReader(reqB))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	for k, v := range c.CustomHeader {
		req.Header.Set(k, v)
	}

	var dErr error
	resp, err := c._do(req)
	if err != nil {
		if resp != nil {
			if jrResp, dErr = decodeResponseBody(resp); dErr != nil {
				err = fmt.Errorf("fail to decode response body err:%+v, httpErr:%+v, httpResp:%+v",
					dErr, err, resp)
				return
			}
			err = jrResp.Error
			return
		}
		return
	}

	if jrResp, dErr = decodeResponseBody(resp); dErr != nil {
		err = fmt.Errorf("fail to decode response body err:%+v, jsonrpcResp:%+v",
			dErr, resp)
		return
	}
	if jrResp.Error != nil {
		err = jrResp.Error
		return
	}
	if respPtr != nil {
		err = json.Unmarshal(jrResp.Result, respPtr)
		if err != nil {
			return
		}
	}
	return
}

func (c *JsonRpcClient) Raw(reqB []byte) (resp *http.Response, err error) {
	req, err := http.NewRequest("POST", c.Endpoint, bytes.NewReader(reqB))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	for k, v := range c.CustomHeader {
		req.Header.Set(k, v)
	}

	return c._do(req)
}

func decodeResponseBody(resp *http.Response) (jrResp *Response, err error) {
	defer resp.Body.Close()
	err = json.NewDecoder(resp.Body).Decode(&jrResp)
	return
}
