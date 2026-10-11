// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package tplink

import (
	"context"
	"errors"
	"fmt"
)

// The Tapo ("smart") request family is the same over KLAP and over
// securePassthrough: {"method", "params"} answered {"error_code",
// "result"}. A hub (H100, H200) or a power strip (P300, P304M) lists its
// children with get_child_device_list, paged by start_index with the total
// in "sum", and passes a request on to one child with control_child
// {"device_id", "requestData": {"method", "params"}}, whose answer is in
// responseData.

// SmartCaller is a Tapo transport: KLAPClient or AESClient.
type SmartCaller interface {
	Call(ctx context.Context, method string, params any) (map[string]any, error)
}

// SmartError is a Tapo request answered with an error code.
type SmartError struct {
	Code   int
	Method string
}

// Error describes the code and the method.
func (e *SmartError) Error() string {
	return fmt.Sprintf("the device answered error %d to %s", e.Code, e.Method)
}

// smartErrUnsupported is the error code of a method the device lacks.
const smartErrUnsupported = -1002

// IsUnsupported reports whether err is a Tapo "method not supported" (or
// "params" error) answer.
func IsUnsupported(err error) bool {
	var se *SmartError
	return errors.As(err, &se) && (se.Code == smartErrUnsupported || se.Code == -1001 || se.Code == -40106)
}

// ChildList reads every child of a hub or strip, page by page.
func ChildList(ctx context.Context, c SmartCaller) ([]map[string]any, error) {
	var out []map[string]any
	for page := 0; page < 20; page++ {
		res, err := c.Call(ctx, "get_child_device_list", map[string]any{"start_index": len(out)})
		if err != nil {
			return nil, err
		}
		list, _ := res["child_device_list"].([]any)
		for _, x := range list {
			if m, ok := x.(map[string]any); ok {
				out = append(out, m)
			}
		}
		sum, ok := num(res["sum"])
		if !ok || len(list) == 0 || len(out) >= int(sum) {
			return out, nil
		}
	}
	return out, nil
}

// ControlChild sends one request to a child through its parent.
func ControlChild(ctx context.Context, c SmartCaller, deviceID, method string, params any) (map[string]any, error) {
	res, err := c.Call(ctx, "control_child", map[string]any{"device_id": deviceID, "requestData": map[string]any{"method": method, "params": params}})
	if err != nil {
		return nil, err
	}
	rd, _ := res["responseData"].(map[string]any)
	if rd == nil {
		return map[string]any{}, nil
	}
	if code, ok := num(rd["error_code"]); ok && code != 0 {
		return nil, &SmartError{Code: int(code), Method: method}
	}
	out, _ := rd["result"].(map[string]any)
	if out == nil {
		out = map[string]any{}
	}
	return out, nil
}
