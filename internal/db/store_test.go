// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package db

import (
	"context"
	"errors"
	"testing"
)

func TestSettingRoundTrip(t *testing.T) {
	s := NewTestDB(t)
	ctx := context.Background()

	if _, err := s.GetSetting(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetSetting(missing) = %v, want ErrNotFound", err)
	}

	if err := s.SetSetting(ctx, "k", "v1"); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetSetting(ctx, "k")
	if err != nil {
		t.Fatal(err)
	}
	if got != "v1" {
		t.Errorf("GetSetting = %q, want %q", got, "v1")
	}

	// 覆盖写：SetSetting 必须是 upsert，不能因主键冲突失败。
	if err := s.SetSetting(ctx, "k", "v2"); err != nil {
		t.Fatalf("overwriting a setting failed: %v", err)
	}
	got, err = s.GetSetting(ctx, "k")
	if err != nil {
		t.Fatal(err)
	}
	if got != "v2" {
		t.Errorf("GetSetting after overwrite = %q, want %q", got, "v2")
	}
}

func TestAppendAndListLogs(t *testing.T) {
	s := NewTestDB(t)
	ctx := context.Background()

	id := int64(7)
	detail := "created something"
	for _, l := range []OperationLog{
		{Action: "create", ResourceType: "certificate", ResourceID: &id, Detail: &detail, Operator: "admin"},
		{Action: "delete", ResourceType: "certificate", Operator: "admin"},
	} {
		if err := s.AppendLog(ctx, l); err != nil {
			t.Fatal(err)
		}
	}

	logs, err := s.ListLogs(ctx, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) != 2 {
		t.Fatalf("len(logs) = %d, want 2", len(logs))
	}
	// 最新优先。
	if logs[0].Action != "delete" {
		t.Errorf("logs[0].Action = %q, want %q (newest first)", logs[0].Action, "delete")
	}
	if logs[0].ResourceID != nil {
		t.Errorf("logs[0].ResourceID = %v, want nil", *logs[0].ResourceID)
	}
	if logs[1].ResourceID == nil || *logs[1].ResourceID != 7 {
		t.Errorf("logs[1].ResourceID = %v, want 7", logs[1].ResourceID)
	}
	if logs[1].Detail == nil || *logs[1].Detail != detail {
		t.Errorf("logs[1].Detail = %v, want %q", logs[1].Detail, detail)
	}
	if logs[0].CreatedAt == "" {
		t.Error("CreatedAt is empty, want the DB default to be populated")
	}
}

func TestAppendLogDefaultsOperator(t *testing.T) {
	s := NewTestDB(t)
	ctx := context.Background()
	if err := s.AppendLog(ctx, OperationLog{Action: "a", ResourceType: "t"}); err != nil {
		t.Fatal(err)
	}
	logs, err := s.ListLogs(ctx, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) != 1 || logs[0].Operator != "admin" {
		t.Errorf("operator = %+v, want admin", logs)
	}
}

func TestListLogsReturnsEmptySliceNotNil(t *testing.T) {
	// 空列表必须序列化成 [] 而不是 null，前端不必写特例。
	s := NewTestDB(t)
	logs, err := s.ListLogs(context.Background(), 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if logs == nil {
		t.Error("ListLogs returned nil, want an empty non-nil slice")
	}
}

func TestListLogsPaginates(t *testing.T) {
	s := NewTestDB(t)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		if err := s.AppendLog(ctx, OperationLog{Action: "a", ResourceType: "t", Operator: "admin"}); err != nil {
			t.Fatal(err)
		}
	}

	tests := []struct {
		name          string
		limit, offset int
		wantLen       int
	}{
		{"取前两条", 2, 0, 2},
		{"偏移后取两条", 2, 2, 2},
		{"偏移到尾部", 2, 4, 1},
		{"偏移越界", 2, 99, 0},
		{"limit 为 0 时用默认值", 0, 0, 5},
		{"limit 为负时用默认值", -3, 0, 5},
		{"limit 超上限时截到 500", 9999, 0, 5},
		{"负偏移当作 0", 2, -1, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logs, err := s.ListLogs(ctx, tt.limit, tt.offset)
			if err != nil {
				t.Fatal(err)
			}
			if len(logs) != tt.wantLen {
				t.Errorf("len = %d, want %d", len(logs), tt.wantLen)
			}
		})
	}
}
