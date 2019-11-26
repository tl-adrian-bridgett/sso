package providers

import (
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/buzzfeed/sso/internal/pkg/sessions"
)

// MockAdminService is an implementation of the Amazon Cognito AdminService to be used for testing
type MockCognitoAdminService struct {
	Members            []string
	Groups             []string
	MembersError       error
	GroupsError        error
	UserName           string
	UserInfoError      error
	GlobalSignOutError error
}

// ListMemberships mocks the ListMemebership function
func (ms *MockCognitoAdminService) ListMemberships(string) ([]string, error) {
	return ms.Members, ms.MembersError
}

// CheckMemberships mocks the CheckMemberships function
func (ms *MockCognitoAdminService) CheckMemberships(string) ([]string, error) {
	return ms.Groups, ms.GroupsError
}

func (ms *MockCognitoAdminService) GetUserInfo(*string) (*cognitoidentityprovider.GetUserOutput, error) {
	userInfo := &cognitoidentityprovider.GetUserOutput{
		Username: &ms.UserName}
	return userInfo, ms.UserInfoError
}

func (ms *MockCognitoAdminService) GlobalSignOut(*sessions.SessionState) error {
	return ms.GlobalSignOutError
}
