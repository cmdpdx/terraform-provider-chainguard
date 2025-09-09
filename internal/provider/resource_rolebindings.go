/*
Copyright 2023 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package provider

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"chainguard.dev/sdk/uidp"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	common "chainguard.dev/sdk/proto/platform/common/v1"
	iam "chainguard.dev/sdk/proto/platform/iam/v1"
	"github.com/chainguard-dev/terraform-provider-chainguard/internal/validators"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                = &rolebindingsResource{}
	_ resource.ResourceWithConfigure   = &rolebindingsResource{}
	_ resource.ResourceWithImportState = &rolebindingsResource{}
)

// NewRolebindingsResource is a helper function to simplify the provider implementation.
func NewRolebindingsResource() resource.Resource {
	return &rolebindingsResource{}
}

// rolebindingsResource is the resource implementation.
type rolebindingsResource struct {
	managedResource
}

type rolebindingsResourceModel struct {
	ID         types.String `tfsdk:"id"`
	Group      types.String `tfsdk:"group"`
	Identities types.Set    `tfsdk:"identities"`
	Role       types.String `tfsdk:"role"`
	Bindings   types.List   `tfsdk:"bindings"`
}

var roleBindingsResourceModelAttributeTypes = map[string]attr.Type{
	"id":       types.StringType,
	"group":    types.StringType,
	"role":     types.StringType,
	"identity": types.StringType,
}

func (r *rolebindingsResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.configure(ctx, req, resp)
}

// Metadata returns the resource type name.
func (r *rolebindingsResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_rolebindings"
}

// Schema defines the schema for the resource.
func (r *rolebindingsResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "IAM Rolebidning in the Chainguard platform.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "A constructed identifier for the role binding batch; binding IDs are ordered alphabetically and concatenated with : to form this id.",
				Computed:    true,
			},
			"group": schema.StringAttribute{
				Description:   "The id of the IAM group to grant the identities access to with the role's capabilities.",
				Required:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
				Validators:    []validator.String{validators.UIDP(false /* allowRootSentinel */)},
			},
			"role": schema.StringAttribute{
				Description: "The role to grant identities at the scope of the IAM group.",
				Required:    true,
				Validators:  []validator.String{validators.UIDP(false /* allowRootSentinel */)},
			},
			"identities": schema.SetAttribute{
				Description: "The ids of identities to grant role's capabilities to at the scope of the IAM group.",
				Required:    true,
				ElementType: types.StringType,
				Validators: []validator.Set{
					setvalidator.SizeAtLeast(1),
					setvalidator.ValueStringsAre(validators.UIDP(false /* allowRootSentinel */)),
				},
			},
			"bindings": schema.ListNestedAttribute{
				Description: "The resulting role bindings created by this resource.",
				Computed:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Description: "The UIDP of this role binding.",
							Computed:    true,
						},
						"group": schema.StringAttribute{
							Description: "The id of the IAM group this identity has been granted a role in. Always the parent of the binding id.",
							Computed:    true,
						},
						"identity": schema.StringAttribute{
							Description: "The id of an identity granted role's capabilities to at the scope of the IAM group.",
							Computed:    true,
						},
						"role": schema.StringAttribute{
							Description: "The id of the role granted to identity at the scope of the IAM group.",
							Computed:    true,
						},
					},
				},
			},
		},
	}
}

// TODO: fix
// ImportState imports resources by ID into the current Terraform state.
func (r *rolebindingsResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func createBatch(ctx context.Context, client iam.Clients, parentID, roleID string, identities []string) ([]*rolebindingResourceModel, error) {
	if len(identities) == 0 {
		return []*rolebindingResourceModel{}, nil
	}

	cbr := &iam.CreateRoleBindingBatchRequest{
		Parent:       parentID,
		RoleBindings: make([]*iam.RoleBinding, 0, len(identities)),
	}
	for _, id := range identities {
		cbr.RoleBindings = append(cbr.RoleBindings, &iam.RoleBinding{
			Identity: id,
			Role:     roleID,
		})
	}

	batch, err := client.RoleBindings().CreateBatch(ctx, cbr)
	if err != nil {
		return nil, err
	}

	bindings := make([]*rolebindingResourceModel, 0, len(batch.RoleBindings))
	for _, b := range batch.RoleBindings {
		bindings = append(bindings, &rolebindingResourceModel{
			ID:       types.StringValue(b.Id),
			Group:    types.StringValue(uidp.Parent(b.Id)),
			Role:     types.StringValue(b.Role),
			Identity: types.StringValue(b.Identity),
		})
	}

	return bindings, nil
}

func generateID(rbl []*rolebindingResourceModel) string {
	if len(rbl) == 0 {
		return ""
	}

	sort.Slice(rbl, func(i, j int) bool {
		return rbl[i].ID.ValueString() < rbl[j].ID.ValueString()
	})

	var b strings.Builder
	for _, rb := range rbl {
		b.WriteString(rb.ID.ValueString() + ":")
	}

	// Strip the last trailing :
	return strings.TrimSuffix(b.String(), ":")
}

func rolebindingResourceModelSliceToList(ctx context.Context, bindings []*rolebindingResourceModel) (types.List, diag.Diagnostics) {
	var diags diag.Diagnostics
	elems := make([]attr.Value, 0, len(bindings))
	for _, b := range bindings {
		var o types.Object
		o, diags = types.ObjectValueFrom(ctx, roleBindingsResourceModelAttributeTypes, b)
		if diags.HasError() {
			return types.List{}, diags
		}
		elems = append(elems, o)
	}

	return types.ListValue(types.ObjectType{}.WithAttributeTypes(roleBindingsResourceModelAttributeTypes), elems)
}

// Create creates the resource and sets the initial Terraform state.
func (r *rolebindingsResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	// Read the plan data into the resource model.
	var plan rolebindingsResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	tflog.Info(ctx, fmt.Sprintf("create rolebinding request: group=%s, role=%s, identities=%s", plan.Group, plan.Role, plan.Identities))

	// Create the role bindings.
	ids := make([]string, 0, len(plan.Identities.Elements()))
	resp.Diagnostics.Append(plan.Identities.ElementsAs(ctx, &ids, false /* allowUnhandled */)...)
	if resp.Diagnostics.HasError() {
		return
	}

	bindings, err := createBatch(ctx, r.prov.client.IAM(), plan.Group.ValueString(), plan.Role.ValueString(), ids)
	if err != nil {
		resp.Diagnostics.Append(errorToDiagnostic(err, "failed to create role bindings"))
		return
	}

	// Save bindings details in the state.
	plan.Bindings, resp.Diagnostics = rolebindingResourceModelSliceToList(ctx, bindings)
	if resp.Diagnostics.HasError() {
		return
	}
	plan.ID = types.StringValue(generateID(bindings))
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Read refreshes the Terraform state with the latest data.
func (r *rolebindingsResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	// Read the current state into the resource model.
	var state rolebindingsResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	tflog.Info(ctx, fmt.Sprintf("read rolebinding request: group=%s, identities=%s", state.Group, state.Identities))

	// Fetch all role bindings from the parent group
	parentID := state.Group.ValueString()
	bindingList, err := r.prov.client.IAM().RoleBindings().List(ctx, &iam.RoleBindingFilter{
		Uidp: &common.UIDPFilter{
			ChildrenOf: parentID,
		},
	})
	if err != nil {
		resp.Diagnostics.Append(errorToDiagnostic(err, "failed to list role bindings"))
		return
	}

	// Filter by the role and identities we want
	elems := state.Identities.Elements()
	ids := make(map[string]struct{}, len(elems))
	for _, id := range elems {
		ids[id.String()] = struct{}{}
	}

	bindings := make([]*rolebindingResourceModel, 0, len(bindingList.GetItems()))
	for _, b := range bindingList.GetItems() {
		// Skip identities not in the state
		if _, ok := ids[b.Identity]; !ok {
			continue
		}
		// Skip bindings for roles not in the state
		if b.Role.Id != state.Role.ValueString() {
			continue
		}
		bindings = append(bindings, &rolebindingResourceModel{
			ID:       types.StringValue(b.Id),
			Identity: types.StringValue(b.Identity),
			Role:     types.StringValue(b.Role.Id),
			Group:    types.StringValue(uidp.Parent(b.Id)),
		})
	}

	if len(bindings) == 0 {
		// There are no bindings from the platform that match the (group, identity, role) tuple.
		// Possibly deleted outside of TF.
		resp.State.RemoveResource(ctx)
	} else {
		// Set state
		state.Bindings, resp.Diagnostics = rolebindingResourceModelSliceToList(ctx, bindings)
		if resp.Diagnostics.HasError() {
			return
		}
		state.ID = types.StringValue(generateID(bindings))
		resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	}
}

func calculateStateAndPlanDiff(stateBindings []*rolebindingResourceModel, planIdentities types.Set) (identitiesToAdd map[string]interface{}, bindingsToRemove []*rolebindingResourceModel) {
	state := make(map[string]interface{})
	for _, rb := range stateBindings {
		state[rb.Identity.ValueString()] = struct{}{}
	}

	plan := make(map[string]interface{})
	identitiesToAdd = make(map[string]interface{})
	for _, p := range planIdentities.Elements() {
		plan[p.String()] = struct{}{}

		if _, ok := state[p.String()]; !ok {
			identitiesToAdd[p.String()] = struct{}{}
		}
	}

	bindingsToRemove = make([]*rolebindingResourceModel, 0, len(state))
	for _, rb := range stateBindings {
		if _, ok := plan[rb.Identity.ValueString()]; !ok {
			bindingsToRemove = append(bindingsToRemove, rb)
		}
	}

	return identitiesToAdd, bindingsToRemove
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *rolebindingsResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	// Read the plan and current state into the resource model so we can find the diff.
	var data, state rolebindingsResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	tflog.Info(ctx, fmt.Sprintf("update rolebinding request: parent=%s, role=%s, identities=%s", data.Group, data.Role, data.Identities))

	// There are a few update scenarios:
	// 1. Group ID changed. Since this is marked as replacement required that should
	//    trigger a delete/replace of the resource.
	// 2. Role ID changed. All existing role bindings need to be updated.
	// 3. Identities added/removed. We need to reconcile the state of the world,
	//    individually removing deleted identity role bindings, and batch creating added identities.
	//    Luckily role binding create is idempotent, which will be helpful.

	// Calculate set of identities added and removed
	stateBindings := []*rolebindingResourceModel{}
	resp.Diagnostics.Append(state.Bindings.ElementsAs(ctx, stateBindings, false /* allowUnhandled */)...)
	if resp.Diagnostics.HasError() {
		return
	}

	identitiesToAdd, bindingsToRemove := calculateStateAndPlanDiff(stateBindings, data.Identities)

	// We will always need to delete role bindings for identities removed, regardless of role ID change.
	removedIDs := make(map[string]interface{}, len(bindingsToRemove))
	for _, rb := range bindingsToRemove {
		removedIDs[rb.ID.ValueString()] = struct{}{}
		if _, err := r.prov.client.IAM().RoleBindings().Delete(ctx, &iam.DeleteRoleBindingRequest{Id: rb.ID.ValueString()}); err != nil {
			resp.Diagnostics.Append(errorToDiagnostic(err, "failed to delete role binding"))
		}
	}
	if resp.Diagnostics.HasError() {
		return
	}

	// Create bindings for new identities in a batch
	ids := make([]string, 0, len(identitiesToAdd))
	for id := range identitiesToAdd {
		ids = append(ids, id)
	}
	bindings, err := createBatch(ctx, r.prov.client.IAM(), data.Group.ValueString(), data.Role.ValueString(), ids)
	if err != nil {
		resp.Diagnostics.Append(errorToDiagnostic(err, "failed to create role bindings"))
		return
	}

	// Update the remaining bindings if the role has changed
	dataBindings := []*rolebindingResourceModel{}
	resp.Diagnostics.Append(state.Bindings.ElementsAs(ctx, dataBindings, false /* allowUnhandled */)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if data.Role.ValueString() != state.Role.ValueString() {
		for _, rb := range dataBindings {
			// Skip bindings we've removed
			if _, ok := removedIDs[rb.ID.ValueString()]; ok {
				continue
			}
			binding, err := r.prov.client.IAM().RoleBindings().Update(ctx, &iam.RoleBinding{
				Id:       rb.ID.ValueString(),
				Identity: rb.Identity.ValueString(),
				Role:     data.Role.ValueString(),
			})
			if err != nil {
				resp.Diagnostics.Append(errorToDiagnostic(err, fmt.Sprintf("failed to update rolebinding %q", rb.ID.ValueString())))
				// should we exit here or continue to update more?
				return
			}
			bindings = append(bindings, &rolebindingResourceModel{
				ID:       types.StringValue(binding.Id),
				Role:     types.StringValue(binding.Role),
				Identity: types.StringValue(binding.Identity),
				Group:    types.StringValue(uidp.Parent(binding.Id)),
			})
		}
	}

	// Set state
	data.Bindings, resp.Diagnostics = rolebindingResourceModelSliceToList(ctx, bindings)
	if resp.Diagnostics.HasError() {
		return
	}
	data.ID = types.StringValue(generateID(bindings))
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *rolebindingsResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	// Read the current state into the resource model.
	var state rolebindingsResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	tflog.Info(ctx, fmt.Sprintf("delete rolebinding request: parent=%s, role=%s, identities=%s", state.Group, state.Role, state.Identities))

	stateBindings := []*rolebindingResourceModel{}
	resp.Diagnostics.Append(state.Bindings.ElementsAs(ctx, stateBindings, false /* allowUnhandled */)...)
	if resp.Diagnostics.HasError() {
		return
	}
	for _, rb := range stateBindings {
		id := rb.ID.ValueString()
		_, err := r.prov.client.IAM().RoleBindings().Delete(ctx, &iam.DeleteRoleBindingRequest{
			Id: id,
		})
		if err != nil {
			// Collect the errors, but don't quit
			resp.Diagnostics.Append(errorToDiagnostic(err, fmt.Sprintf("failed to delete rolebinding %q", id)))
		}
	}
}
