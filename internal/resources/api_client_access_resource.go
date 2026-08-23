package resources

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/Trozz/terraform-provider-pocketid/internal/client"
)

var (
	_ resource.Resource                = &apiClientAccessResource{}
	_ resource.ResourceWithConfigure   = &apiClientAccessResource{}
	_ resource.ResourceWithImportState = &apiClientAccessResource{}
)

// NewAPIClientAccessResource creates the resource implementation for explicit
// OIDC-client access to a Pocket-ID API resource.
func NewAPIClientAccessResource() resource.Resource {
	return &apiClientAccessResource{}
}

type apiClientAccessResource struct {
	client *client.Client
}

type apiClientAccessResourceModel struct {
	ID                         types.String `tfsdk:"id"`
	APIID                      types.String `tfsdk:"api_id"`
	ClientID                   types.String `tfsdk:"client_id"`
	UserDelegatedAccess        types.Bool   `tfsdk:"user_delegated_access"`
	ClientAccess               types.Bool   `tfsdk:"client_access"`
	UserDelegatedPermissionIDs types.Set    `tfsdk:"user_delegated_permission_ids"`
	ClientPermissionIDs        types.Set    `tfsdk:"client_permission_ids"`
}

// Metadata returns the resource type name.
func (r *apiClientAccessResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_api_client_access"
}

// Schema defines the API/client access schema.
func (r *apiClientAccessResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages one OIDC client's explicit access to a Pocket-ID API resource.",
		MarkdownDescription: `Manages one OIDC client's explicit access to a Pocket-ID API resource.

Set client_access and client_permission_ids to grant client-credentials (machine-to-machine) access. A client must be confidential (is_public = false) for Pocket-ID to retain client-credentials grants. Permission IDs can be obtained from pocketid_api.permission_ids.`,
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "The composite API/client access ID.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"api_id": schema.StringAttribute{
				Description: "The Pocket-ID API resource ID.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"client_id": schema.StringAttribute{
				Description: "The Pocket-ID OIDC client ID.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"user_delegated_access": schema.BoolAttribute{
				Description: "Whether the client may request this audience in user-delegated flows.",
				Required:    true,
			},
			"client_access": schema.BoolAttribute{
				Description: "Whether the client may request this audience with the client credentials grant.",
				Required:    true,
			},
			"user_delegated_permission_ids": schema.SetAttribute{
				Description: "Permission IDs granted in user-delegated flows.",
				Required:    true,
				ElementType: types.StringType,
			},
			"client_permission_ids": schema.SetAttribute{
				Description: "Permission IDs granted in client-credentials flows.",
				Required:    true,
				ElementType: types.StringType,
			},
		},
	}
}

// Configure adds the provider configured client to the resource.
func (r *apiClientAccessResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	c, ok := req.ProviderData.(*client.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *client.Client, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}

	r.client = c
}

// Create grants the configured access and records the access relation.
func (r *apiClientAccessResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan apiClientAccessResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	grant, diags := apiClientAccessGrantFromModel(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	applied, err := r.client.UpdateAPIClientAccess(plan.APIID.ValueString(), plan.ClientID.ValueString(), grant)
	if err != nil {
		resp.Diagnostics.AddError("Error granting API client access", "Could not grant API client access, unexpected error: "+err.Error())
		return
	}

	resp.Diagnostics.Append(apiClientAccessToModel(ctx, plan.APIID.ValueString(), plan.ClientID.ValueString(), applied, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Read refreshes the managed explicit grant. API entries inherited only through
// CIMD do not count as this resource because they are not editable per client.
func (r *apiClientAccessResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state apiClientAccessResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	grants, err := r.client.ListClientAPIs(state.ClientID.ValueString())
	if err != nil {
		if isNotFoundError(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Error reading API client access", "Could not list API client access: "+err.Error())
		return
	}

	for _, grant := range grants {
		if grant.API.ID != state.APIID.ValueString() {
			continue
		}
		if !hasExplicitAPIClientGrant(&grant) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.Append(apiClientAccessToModel(ctx, state.APIID.ValueString(), state.ClientID.ValueString(), &grant.APIClientGrant, &state)...)
		if resp.Diagnostics.HasError() {
			return
		}
		resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
		return
	}

	resp.State.RemoveResource(ctx)
}

// Update replaces the complete explicit grant for the API/client pair.
func (r *apiClientAccessResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan apiClientAccessResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	grant, diags := apiClientAccessGrantFromModel(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	applied, err := r.client.UpdateAPIClientAccess(plan.APIID.ValueString(), plan.ClientID.ValueString(), grant)
	if err != nil {
		resp.Diagnostics.AddError("Error updating API client access", "Could not update API client access, unexpected error: "+err.Error())
		return
	}

	resp.Diagnostics.Append(apiClientAccessToModel(ctx, plan.APIID.ValueString(), plan.ClientID.ValueString(), applied, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Delete revokes all explicit access for the API/client pair.
func (r *apiClientAccessResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state apiClientAccessResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Deleting API client access", map[string]any{
		"api_id":    state.APIID.ValueString(),
		"client_id": state.ClientID.ValueString(),
	})
	if err := r.client.DeleteAPIClientAccess(state.APIID.ValueString(), state.ClientID.ValueString()); err != nil && !isNotFoundError(err) {
		resp.Diagnostics.AddError("Error deleting API client access", "Could not delete API client access, unexpected error: "+err.Error())
	}
}

// ImportState imports an API/client grant using the form
// <url-escaped-api-id>/<url-escaped-client-id>.
func (r *apiClientAccessResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	parts := strings.SplitN(req.ID, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		resp.Diagnostics.AddError("Invalid API client access import ID", "Expected import ID in the form <url-escaped-api-id>/<url-escaped-client-id>.")
		return
	}

	apiID, err := url.QueryUnescape(parts[0])
	if err != nil {
		resp.Diagnostics.AddError("Invalid API client access import ID", "Could not decode API ID: "+err.Error())
		return
	}
	clientID, err := url.QueryUnescape(parts[1])
	if err != nil {
		resp.Diagnostics.AddError("Invalid API client access import ID", "Could not decode client ID: "+err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("api_id"), apiID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("client_id"), clientID)...)
}

func apiClientAccessGrantFromModel(ctx context.Context, model *apiClientAccessResourceModel) (*client.APIClientGrant, diag.Diagnostics) {
	var diags diag.Diagnostics
	userPermissions, userDiags := apiClientAccessPermissionIDs(ctx, model.UserDelegatedPermissionIDs)
	diags.Append(userDiags...)
	clientPermissions, clientDiags := apiClientAccessPermissionIDs(ctx, model.ClientPermissionIDs)
	diags.Append(clientDiags...)
	if diags.HasError() {
		return nil, diags
	}

	return &client.APIClientGrant{
		UserDelegatedAccess:        model.UserDelegatedAccess.ValueBool(),
		ClientAccess:               model.ClientAccess.ValueBool(),
		UserDelegatedPermissionIDs: userPermissions,
		ClientPermissionIDs:        clientPermissions,
	}, diags
}

func apiClientAccessPermissionIDs(ctx context.Context, values types.Set) ([]string, diag.Diagnostics) {
	var diags diag.Diagnostics
	if values.IsNull() || values.IsUnknown() {
		return []string{}, diags
	}

	var result []string
	diags.Append(values.ElementsAs(ctx, &result, false)...)
	if result == nil {
		result = []string{}
	}
	return result, diags
}

func apiClientAccessToModel(ctx context.Context, apiID, clientID string, grant *client.APIClientGrant, model *apiClientAccessResourceModel) diag.Diagnostics {
	var diags diag.Diagnostics
	model.ID = types.StringValue(apiClientAccessID(apiID, clientID))
	model.APIID = types.StringValue(apiID)
	model.ClientID = types.StringValue(clientID)
	model.UserDelegatedAccess = types.BoolValue(grant.UserDelegatedAccess)
	model.ClientAccess = types.BoolValue(grant.ClientAccess)

	userPermissions, userDiags := types.SetValueFrom(ctx, types.StringType, grant.UserDelegatedPermissionIDs)
	diags.Append(userDiags...)
	model.UserDelegatedPermissionIDs = userPermissions
	clientPermissions, clientDiags := types.SetValueFrom(ctx, types.StringType, grant.ClientPermissionIDs)
	diags.Append(clientDiags...)
	model.ClientPermissionIDs = clientPermissions
	return diags
}

func apiClientAccessID(apiID, clientID string) string {
	return url.QueryEscape(apiID) + "/" + url.QueryEscape(clientID)
}

func hasExplicitAPIClientGrant(grant *client.ClientAPIGrant) bool {
	return grant.UserDelegatedAccess || grant.ClientAccess || len(grant.UserDelegatedPermissionIDs) > 0 || len(grant.ClientPermissionIDs) > 0
}
