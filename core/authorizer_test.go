package core

import (
	"testing"
)

func TestNoopAuthorizer(t *testing.T) {
	request := &GetUserDataRequest{
		Code:      "010190-12165",
		FirstName: "John",
		LastName:  "Doe",
		Email:     "john@example.com",
	}

	authorizer := NewNoopAuthorizer()
	result, err := authorizer.GetUserData(nil, request)

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	expected := &UserData{
		UserID:     "010190-12165",
		PersonCode: "010190-12165",
		FirstName:  "John",
		LastName:   "Doe",
		Email:      "john@example.com",
	}

	if result.UserID != expected.UserID {
		t.Errorf("UserID: got %v, want %v", result.UserID, expected.UserID)
	}
	if result.PersonCode != expected.PersonCode {
		t.Errorf("PersonCode: got %v, want %v", result.PersonCode, expected.PersonCode)
	}
	if result.FirstName != expected.FirstName {
		t.Errorf("FirstName: got %v, want %v", result.FirstName, expected.FirstName)
	}
	if result.LastName != expected.LastName {
		t.Errorf("LastName: got %v, want %v", result.LastName, expected.LastName)
	}
	if result.Email != expected.Email {
		t.Errorf("Email: got %v, want %v", result.Email, expected.Email)
	}
}
