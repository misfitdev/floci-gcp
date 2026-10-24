package io.floci.gcp.services.iam;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.DefaultValue;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.PATCH;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import java.util.Map;

/**
 * IAM v1 {@code projects.roles}. The path has more literal characters than {@link IamController}'s
 * {@code /v1/projects} catch-all, so JAX-RS selects this resource for role paths.
 */
@Path("/v1/projects/{project}/roles")
@ApplicationScoped
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class IamRolesController {

    private final IamRoleService service;

    @Inject
    public IamRolesController(IamRoleService service) {
        this.service = service;
    }

    @POST
    public Response create(@PathParam("project") String project, Map<String, Object> body) {
        return IamRoleResponses.create(service, "projects/" + project, body);
    }

    @GET
    public Response list(@PathParam("project") String project, @QueryParam("view") String view,
            @QueryParam("showDeleted") @DefaultValue("false") boolean showDeleted,
            @QueryParam("pageSize") @DefaultValue("0") int pageSize, @QueryParam("pageToken") String pageToken) {
        return IamRoleResponses.list(service, "projects/" + project, view, showDeleted, pageSize, pageToken);
    }

    @GET
    @Path("/{role}")
    public Response get(@PathParam("project") String project, @PathParam("role") String role) {
        return Response.ok(service.get("projects/" + project + "/roles/" + role)).build();
    }

    @PATCH
    @Path("/{role}")
    public Response patch(@PathParam("project") String project, @PathParam("role") String role,
            @QueryParam("updateMask") String updateMask, Map<String, Object> body) {
        return Response.ok(service.update("projects/" + project + "/roles/" + role, body, updateMask)).build();
    }

    @DELETE
    @Path("/{role}")
    @Consumes({MediaType.APPLICATION_JSON, MediaType.APPLICATION_FORM_URLENCODED})
    public Response delete(@PathParam("project") String project, @PathParam("role") String role,
            @QueryParam("etag") String etag) {
        return Response.ok(service.delete("projects/" + project + "/roles/" + role, etag)).build();
    }

    @POST
    @Path("/{role}:undelete")
    public Response undelete(@PathParam("project") String project, @PathParam("role") String role,
            Map<String, Object> body) {
        return IamRoleResponses.undelete(service, "projects/" + project + "/roles/" + role, body);
    }
}
