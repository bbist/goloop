package jsonrpc

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"

	"github.com/labstack/echo"

	"github.com/icon-project/goloop/module"
)

const Version = "2.0"

type Request struct {
	Version string           `json:"jsonrpc" validate:"required,version"`
	Method  string           `json:"method" validate:"required"`
	Params  *json.RawMessage `json:"params,omitempty"`
	ID      *json.RawMessage `json:"id"`
}

type Response struct {
	Version string           `json:"jsonrpc"`
	Result  interface{}      `json:"result,omitempty"`
	Error   *Error           `json:"error,omitempty"`
	ID      *json.RawMessage `json:"id,omitempty"`
}

type Context struct {
	echo.Context
}

func (ctx *Context) Chain() (module.Chain, error) {
	chain, ok := ctx.Get("chain").(module.Chain)
	if chain == nil || !ok {
		return nil, errors.New("chain is empty")
	}
	return chain, nil
}

type Params struct {
	rawMessage *json.RawMessage
	validator  echo.Validator
}

func (p *Params) Convert(v interface{}) error {
	if p.rawMessage == nil {
		return ErrInvalidParams()
	}
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Ptr || rv.IsNil() {
		return errors.New("invalid convert error")
	}
	if err := json.Unmarshal(*p.rawMessage, v); err != nil {
		fmt.Println(err.Error())
		return ErrInvalidParams()
	}
	if err := p.validator.Validate(v); err != nil {
		fmt.Println(err.Error())
		return ErrInvalidParams()
	}
	return nil
}

func (p *Params) RawMessage() []byte {
	bs, _ := p.rawMessage.MarshalJSON()
	return bs
}

func (p *Params) IsEmpty() bool {
	if p.rawMessage == nil {
		return true
	}
	return false
}
