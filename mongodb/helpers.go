package mongodb

import (
	"fmt"
	"sort"

	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"go.mongodb.org/mongo-driver/bson"
)

func validateDiagFunc(validateFunc func(interface{}, string) ([]string, []error)) schema.SchemaValidateDiagFunc {
	return func(i interface{}, path cty.Path) diag.Diagnostics {
		warnings, errs := validateFunc(i, fmt.Sprintf("%+v", path))
		var diags diag.Diagnostics
		for _, warning := range warnings {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Warning,
				Summary:  warning,
			})
		}
		for _, err := range errs {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  err.Error(),
			})
		}
		return diags
	}
}

func getActions(privilegeDto PrivilegeDto) []string {
	var actions []string = privilegeDto.Actions
	sort.Strings(actions)
	return actions
}

func getPrivilegesFromDto(privilegeDtos []PrivilegeDto) []bson.D {
	var privileges []bson.D

	for _, element := range privilegeDtos {
		var resource bson.D
		if element.Cluster {
			resource = bson.D{{Key: "cluster", Value: true}}
		} else {
			resource = bson.D{
				{Key: "db", Value: element.Db},
				{Key: "collection", Value: element.Collection},
			}
		}
		privileges = append(privileges, bson.D{
			{Key: "resource", Value: resource},
			{Key: "actions", Value: getActions(element)},
		})
	}

	return privileges
}

func getRoleManagementCommand(commandName string, roleName string, roles []Role, privileges []PrivilegeDto) bson.D {
	rolesArr := bson.A{}

	for _, role := range roles {
		rolesArr = append(rolesArr, role)
	}

	privilegesArr := bson.A{}

	for _, privilege := range getPrivilegesFromDto(privileges) {
		privilegesArr = append(privilegesArr, privilege)
	}

	return bson.D{
		{Key: commandName, Value: roleName},
		{Key: "privileges", Value: privilegesArr},
		{Key: "roles", Value: rolesArr},
	}
}
