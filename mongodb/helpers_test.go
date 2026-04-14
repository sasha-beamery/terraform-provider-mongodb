package mongodb

import (
	"reflect"
	"testing"

	"go.mongodb.org/mongo-driver/bson"
)

func TestGetActions(t *testing.T) {
	privilege := PrivilegeDto{Db: "test", Collection: "test", Actions: []string{"find", "update", "remove", "insert"}}

	expectedActions := []string{"find", "insert", "remove", "update"}
	var actions []string = getActions(privilege)

	if reflect.DeepEqual(actions, expectedActions) == false {
		t.Errorf("Obtained actions = %v; want %v", actions, expectedActions)
	}
}

func TestGetPrivilegesFromDto(t *testing.T) {
	privilegesDto := PrivilegeDto{Db: "test", Collection: "test", Actions: []string{"remove", "update", "insert", "find"}}
	privilegesDto2 := PrivilegeDto{Db: "test", Collection: "test2", Actions: []string{"remove", "update", "find"}}

	expectedPrivileges := []bson.D{
		{
			{Key: "resource", Value: bson.D{
				{Key: "db", Value: "test"},
				{Key: "collection", Value: "test"},
			}},
			{Key: "actions", Value: []string{"find", "insert", "remove", "update"}},
		},
		{
			{Key: "resource", Value: bson.D{
				{Key: "db", Value: "test"},
				{Key: "collection", Value: "test2"},
			}},
			{Key: "actions", Value: []string{"find", "remove", "update"}},
		},
	}
	privileges := getPrivilegesFromDto([]PrivilegeDto{privilegesDto, privilegesDto2})

	if reflect.DeepEqual(expectedPrivileges, privileges) == false {
		t.Errorf("Obtained privileges = %v; want %v", privileges, expectedPrivileges)
	}
}

func TestValidateClusterPrivilege(t *testing.T) {
	// The privilege `db` field has no Default in the schema, so Terraform sets it
	// to "" when the user does not specify it. The boundary for the cluster check
	// is therefore db != "": an empty string is the legitimate "not set" value and
	// must not be rejected, while any explicit non-empty value (including "admin")
	// is a misconfiguration because cluster = true has no database scope.
	tests := []struct {
		name    string
		priv    map[string]interface{}
		wantErr bool
	}{
		{
			// Normal cluster privilege — db and collection left unset (zero value "").
			name:    "cluster only is valid",
			priv:    map[string]interface{}{"cluster": true, "db": "", "collection": ""},
			wantErr: false,
		},
		{
			name:    "db and collection only is valid",
			priv:    map[string]interface{}{"cluster": false, "db": "mydb", "collection": "mycol"},
			wantErr: false,
		},
		{
			name:    "neither cluster nor db/collection is valid",
			priv:    map[string]interface{}{"cluster": false, "db": "", "collection": ""},
			wantErr: false,
		},
		{
			// Someone might set db = "admin" assuming that's where cluster roles live;
			// this must be rejected because cluster = true has no db scope at all.
			name:    "cluster true with db set to admin is invalid",
			priv:    map[string]interface{}{"cluster": true, "db": "admin", "collection": ""},
			wantErr: true,
		},
		{
			name:    "cluster true with db set to other value is invalid",
			priv:    map[string]interface{}{"cluster": true, "db": "mydb", "collection": ""},
			wantErr: true,
		},
		{
			name:    "cluster true with collection set is invalid",
			priv:    map[string]interface{}{"cluster": true, "db": "", "collection": "mycol"},
			wantErr: true,
		},
		{
			name:    "cluster true with both db and collection set is invalid",
			priv:    map[string]interface{}{"cluster": true, "db": "mydb", "collection": "mycol"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateClusterPrivilege(tt.priv)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateClusterPrivilege() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGetPrivilegesFromDtoCluster(t *testing.T) {
	clusterDto := PrivilegeDto{Cluster: true, Actions: []string{"replSetGetStatus", "replSetGetConfig"}}

	expectedPrivileges := []bson.D{
		{
			{Key: "resource", Value: bson.D{
				{Key: "cluster", Value: true},
			}},
			{Key: "actions", Value: []string{"replSetGetConfig", "replSetGetStatus"}},
		},
	}
	privileges := getPrivilegesFromDto([]PrivilegeDto{clusterDto})

	if reflect.DeepEqual(expectedPrivileges, privileges) == false {
		t.Errorf("Obtained privileges = %v; want %v", privileges, expectedPrivileges)
	}
}
