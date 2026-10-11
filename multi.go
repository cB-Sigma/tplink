// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package tplink

import (
	"context"
	"errors"
	"fmt"
)

// A Tapo device takes several requests in one with multipleRequest
// {"requests": [{"method", "params"}, ...]}, answering
// {"responses": [{"method", "error_code", "result"}, ...]}. Devices limit
// how many fit in one, and some firmware refuses the batch as a whole
// (unknown method, or a JSON or internal error); then the requests go one
// by one. A device stops answering a batch at its first failing request,
// so answers missing from a batch are asked again one by one.

// SmartRequest is one request of a batch.
type SmartRequest struct {
	Method string
	Params any // nil for none
}

// SmartResult is the answer to one request of a batch: Result, or Err (a
// *SmartError when the device answered an error code).
type SmartResult struct {
	Method string
	Result map[string]any
	Err    error
}

// DefaultBatchSize is how many requests MultiCall puts in one
// multipleRequest when the caller does not say.
const DefaultBatchSize = 5

// MultiCall sends the requests in multipleRequest batches of batch (0:
// DefaultBatchSize; 1: one by one) and returns one result per request, in
// order. A device that refuses the batch as a whole is asked one request
// at a time. The error is set only when the transport failed.
func MultiCall(ctx context.Context, c SmartCaller, reqs []SmartRequest, batch int) ([]SmartResult, error) {
	if batch <= 0 {
		batch = DefaultBatchSize
	}
	out := make([]SmartResult, len(reqs))
	done := make([]bool, len(reqs))
	if batch > 1 {
		for start := 0; start < len(reqs); start += batch {
			end := min(start+batch, len(reqs))
			list := make([]any, 0, end-start)
			for _, r := range reqs[start:end] {
				m := map[string]any{"method": r.Method}
				if r.Params != nil {
					m["params"] = r.Params
				}
				list = append(list, m)
			}
			res, err := c.Call(ctx, "multipleRequest", map[string]any{"requests": list})
			if err != nil {
				var se *SmartError
				if errors.As(err, &se) {
					// The batch was refused as a whole (an unknown method, a
					// JSON or internal error, or another code): ask one by one.
					break
				}
				return nil, err
			}
			matchResponses(res, reqs[start:end], out[start:end], done[start:end])
		}
	}
	for i, r := range reqs {
		if done[i] {
			continue
		}
		res, err := c.Call(ctx, r.Method, r.Params)
		var se *SmartError
		if err != nil && !errors.As(err, &se) {
			return nil, err
		}
		out[i] = SmartResult{Method: r.Method, Result: res, Err: err}
	}
	return out, nil
}

// matchResponses fills the results of one batch from its answer, matching
// answers to requests by method in order (one method may be asked twice).
func matchResponses(res map[string]any, reqs []SmartRequest, out []SmartResult, done []bool) {
	list, _ := res["responses"].([]any)
	for _, x := range list {
		m, _ := x.(map[string]any)
		meth := str(m["method"])
		if meth == "" {
			continue
		}
		for i, r := range reqs {
			if done[i] || r.Method != meth {
				continue
			}
			done[i] = true
			out[i] = SmartResult{Method: meth}
			if code, ok := num(m["error_code"]); ok && code != 0 {
				out[i].Err = &SmartError{Code: int(code), Method: meth}
				break
			}
			out[i].Result, _ = m["result"].(map[string]any)
			if out[i].Result == nil {
				out[i].Result = map[string]any{}
			}
			break
		}
	}
}

// SmartList reads a list the device answers in pages ({"start_index",
// "sum", and the list under listKey}), asking from start_index until sum
// entries are read. params are sent with each page (start_index is set).
// It returns the entries and the first page's other fields.
func SmartList(ctx context.Context, c SmartCaller, method, listKey string, params map[string]any) ([]map[string]any, map[string]any, error) {
	var out []map[string]any
	var first map[string]any
	for page := 0; page < 50; page++ {
		p := map[string]any{}
		for k, v := range params {
			p[k] = v
		}
		p["start_index"] = len(out)
		res, err := c.Call(ctx, method, p)
		if err != nil {
			return nil, nil, err
		}
		if first == nil {
			first = res
		}
		list, _ := res[listKey].([]any)
		for _, x := range list {
			if m, ok := x.(map[string]any); ok {
				out = append(out, m)
			}
		}
		sum, ok := num(res["sum"])
		if !ok || len(list) == 0 || len(out) >= int(sum) {
			break
		}
	}
	return out, first, nil
}

// Components asks component_nego: the device's components (firmware
// features such as "energy_monitoring", "countdown", "light_strip") with
// their version codes. The versions choose request shapes.
func Components(ctx context.Context, c SmartCaller) (map[string]int, error) {
	res, err := c.Call(ctx, "component_nego", nil)
	if err != nil {
		return nil, err
	}
	return componentMap(res["component_list"]), nil
}

func componentMap(v any) map[string]int {
	out := map[string]int{}
	list, _ := v.([]any)
	for _, x := range list {
		m, _ := x.(map[string]any)
		if id := str(m["id"]); id != "" {
			n, _ := num(m["ver_code"])
			out[id] = int(n)
		}
	}
	return out
}

// ChildComponents asks a hub or strip for its children's components
// (get_child_device_component_list, paged), by child device_id.
func ChildComponents(ctx context.Context, c SmartCaller) (map[string]map[string]int, error) {
	list, _, err := SmartList(ctx, c, "get_child_device_component_list", "child_component_list", nil)
	if err != nil {
		return nil, err
	}
	out := map[string]map[string]int{}
	for _, m := range list {
		out[str(m["device_id"])] = componentMap(m["component_list"])
	}
	return out, nil
}

// MultiCallChild sends several requests to one child of a hub or strip in
// one control_child carrying a multipleRequest, and returns one result
// per request, in order. A child that refuses the batch is asked one
// request at a time.
func MultiCallChild(ctx context.Context, c SmartCaller, deviceID string, reqs []SmartRequest) ([]SmartResult, error) {
	return MultiCall(ctx, TapoDevice{Caller: c, ChildID: deviceID}, reqs, len(reqs))
}

// errNoResult is a typed helper's error for an answer without the field it
// reads.
func errNoResult(method, field string) error {
	return fmt.Errorf("the device's %s answer has no %s", method, field)
}
