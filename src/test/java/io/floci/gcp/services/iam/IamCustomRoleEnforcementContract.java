package io.floci.gcp.services.iam;

import com.google.iam.v1.Binding;
import com.google.iam.v1.GetIamPolicyRequest;
import com.google.iam.v1.IAMPolicyGrpc;
import com.google.iam.v1.Policy;
import com.google.iam.v1.SetIamPolicyRequest;
import com.google.iam.v1.TestIamPermissionsRequest;
import com.google.pubsub.v1.DeleteTopicRequest;
import com.google.pubsub.v1.GetTopicRequest;
import com.google.pubsub.v1.PublisherGrpc;
import io.floci.gcp.services.credentials.CredentialTokenService;
import io.floci.gcp.services.iam.model.StoredPolicy;
import io.floci.gcp.services.iam.model.StoredRole;
import io.floci.gcp.services.pubsub.PubSubService;
import io.grpc.Channel;
import io.grpc.ClientInterceptors;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.grpc.Metadata;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.grpc.stub.MetadataUtils;
import io.quarkus.test.common.http.TestHTTPResource;
import io.restassured.response.ValidatableResponse;
import jakarta.inject.Inject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** Shared expectations; denials apply only when {@link #enforced()} and succeed otherwise. */
abstract class IamCustomRoleEnforcementContract {

    @Inject
    IamService policies;
    @Inject
    IamRoleService roles;
    @Inject
    PubSubService pubsub;
    @Inject
    CredentialTokenService tokens;
    @TestHTTPResource
    URI endpoint;

    String projectId;
    String project;
    String member;
    String credential;
    ManagedChannel channel;
    Channel caller;

    abstract boolean enforced();

    @BeforeEach
    void setUp() {
        projectId = "cr-" + UUID.randomUUID().toString().substring(0, 8);
        project = "projects/" + projectId;
        String email = "caller@" + projectId + ".iam.gserviceaccount.com";
        member = "serviceAccount:" + email;
        credential = "Bearer " + tokens.mintImpersonatedToken(email, Instant.now().plusSeconds(300)).getTokenValue();
        channel = ManagedChannelBuilder.forAddress(endpoint.getHost(), endpoint.getPort()).usePlaintext().build();
        Metadata headers = new Metadata();
        headers.put(Metadata.Key.of("authorization", Metadata.ASCII_STRING_MARSHALLER), credential);
        caller = ClientInterceptors.intercept(channel, MetadataUtils.newAttachHeadersInterceptor(headers));
    }

    @AfterEach
    void closeChannel() throws InterruptedException {
        channel.shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
    }

    @Test
    void roleManagementRequiresIamRolesPermissionsAndDenialsLeaveRolesUnchanged() {
        String rolesPath = "/v1/" + project + "/roles";
        Map<String, Object> create = Map.of("roleId", "reader",
                "role", Map.of("title", "Reader", "includedPermissions", List.of("pubsub.topics.get")));

        expectDenied(given().header("Authorization", credential).contentType("application/json").body(create)
                .post(rolesPath).then(), 200);
        if (enforced()) {
            given().get(rolesPath + "/reader").then().statusCode(404);
            expectDenied(given().header("Authorization", credential).get(rolesPath).then(), 200);
        }

        grant(project, "roles/iam.roleViewer", null);
        given().contentType("application/json").body(create).post(rolesPath).then().statusCode(enforced() ? 200 : 409);
        String etag = given().header("Authorization", credential).get(rolesPath + "/reader")
                .then().statusCode(200).body("includedPermissions", equalTo(List.of("pubsub.topics.get")))
                .extract().path("etag");
        given().header("Authorization", credential).get(rolesPath)
                .then().statusCode(200).body("roles[0].name", equalTo(project + "/roles/reader"));
        expectDenied(given().header("Authorization", credential).contentType("application/json")
                .body(Map.of("includedPermissions", List.of("pubsub.topics.delete")))
                .queryParam("updateMask", "includedPermissions").patch(rolesPath + "/reader").then(), 200);
        expectDenied(given().header("Authorization", credential).delete(rolesPath + "/reader").then(), 200);
        if (enforced()) {
            StoredRole unchanged = roles.get(project + "/roles/reader");
            assertEquals(etag, unchanged.getEtag());
            assertEquals(List.of("pubsub.topics.get"), unchanged.getIncludedPermissions());
            assertNull(unchanged.getDeleted());
        }

        grant(project, "roles/iam.roleAdmin", null);
        given().header("Authorization", credential).contentType("application/json")
                .body(Map.of("roleId", "writer", "role", Map.of("includedPermissions", List.of("pubsub.topics.delete"))))
                .post(rolesPath).then().statusCode(200).body("name", equalTo(project + "/roles/writer"));
        given().header("Authorization", credential).contentType("application/json")
                .body(Map.of("title", "Writer")).queryParam("updateMask", "title")
                .patch(rolesPath + "/writer").then().statusCode(200).body("title", equalTo("Writer"));
        given().header("Authorization", credential).delete(rolesPath + "/writer")
                .then().statusCode(200).body("deleted", equalTo(true));
        given().urlEncodingEnabled(false).header("Authorization", credential).contentType("application/json")
                .body(Map.of()).post(rolesPath + "/writer:undelete").then().statusCode(200);
    }

    @Test
    void roleManagementConditionsPermitOnlyTheNamedRole() {
        roles.create(project, "allowed", Map.of());
        roles.create(project, "sibling", Map.of());
        grant(project, "roles/iam.roleAdmin", "resource.name == '" + project + "/roles/allowed'");

        given().header("Authorization", credential).get("/v1/" + project + "/roles/allowed").then().statusCode(200);
        given().header("Authorization", credential).delete("/v1/" + project + "/roles/allowed").then().statusCode(200);
        expectDenied(given().header("Authorization", credential).get("/v1/" + project + "/roles/sibling").then(), 200);
        expectDenied(given().header("Authorization", credential).delete("/v1/" + project + "/roles/sibling").then(), 200);
        expectDenied(given().header("Authorization", credential).contentType("application/json")
                .body(Map.of("roleId", "created")).post("/v1/" + project + "/roles").then(), 200);
        if (enforced()) {
            assertNull(roles.get(project + "/roles/sibling").getDeleted());
        }
    }

    @Test
    void customRoleBindingGrantsExactlyItsIncludedPermissionsOverRestAndGrpc() {
        String topic = project + "/topics/source";
        pubsub.createTopic(topic);
        createRoleViaApi(project, "topicreader", List.of("pubsub.topics.get"));
        grant(project, project + "/roles/topicreader", null);

        given().header("Authorization", credential).get("/v1/" + topic).then().statusCode(200);
        PublisherGrpc.PublisherBlockingStub publisher = PublisherGrpc.newBlockingStub(caller)
                .withDeadlineAfter(5, TimeUnit.SECONDS);
        assertEquals(topic, publisher.getTopic(GetTopicRequest.newBuilder().setTopic(topic).build()).getName());

        List<String> requested = List.of("pubsub.topics.get", "pubsub.topics.delete");
        List<String> expected = enforced() ? List.of("pubsub.topics.get") : requested;
        given().urlEncodingEnabled(false).header("Authorization", credential).contentType("application/json")
                .body(Map.of("permissions", requested)).post("/v1/" + topic + ":testIamPermissions")
                .then().statusCode(200).body("permissions", equalTo(expected));
        assertEquals(expected, IAMPolicyGrpc.newBlockingStub(caller).withDeadlineAfter(5, TimeUnit.SECONDS)
                .testIamPermissions(TestIamPermissionsRequest.newBuilder().setResource(topic)
                        .addAllPermissions(requested).build()).getPermissionsList());

        expectDenied(given().header("Authorization", credential).delete("/v1/" + topic).then(), 200);
        if (enforced()) {
            expectGrpcDenied(() -> publisher.deleteTopic(DeleteTopicRequest.newBuilder().setTopic(topic).build()));
            assertEquals(topic, pubsub.getTopic(topic).getName());
        }
    }

    @Test
    void customRoleAuthorizesIamServiceAccountOperationsItDeclares() {
        String email = "target@" + projectId + ".iam.gserviceaccount.com";
        policies.createServiceAccount(projectId, "target", "original", "");
        createRoleViaApi(project, "accountreader", List.of("iam.serviceAccounts.get"));
        grant(project, project + "/roles/accountreader", null);
        String account = "/v1/" + project + "/serviceAccounts/" + email;

        given().header("Authorization", credential).get(account).then().statusCode(200);
        expectDenied(given().header("Authorization", credential).contentType("application/json")
                .body(Map.of("displayName", "changed")).put(account).then(), 200);
        expectDenied(given().header("Authorization", credential).urlEncodingEnabled(false)
                .contentType("application/json").body(Map.of("scope", List.of("https://www.googleapis.com/auth/cloud-platform")))
                .post("/v1/projects/-/serviceAccounts/" + email + ":generateAccessToken").then(), 200);
        if (enforced()) {
            assertEquals("original", policies.getServiceAccount(projectId, "target").getDisplayName());
        }
    }

    @Test
    void roleEditsDisablingDeletionAndUndeletionApplyToExistingBindingsAndCredentials() {
        String topic = project + "/topics/source";
        pubsub.createTopic(topic);
        String role = "/v1/" + project + "/roles/topicreader";
        createRoleViaApi(project, "topicreader", List.of("pubsub.topics.get"));
        grant(project, project + "/roles/topicreader", null);
        Supplier<ValidatableResponse> read = () -> given().header("Authorization", credential)
                .get("/v1/" + topic).then();

        read.get().statusCode(200);
        patch(role, Map.of("includedPermissions", List.of("pubsub.topics.list")), "includedPermissions");
        expectDenied(read.get(), 200);
        patch(role, Map.of("includedPermissions", List.of("pubsub.topics.get")), "includedPermissions");
        read.get().statusCode(200);

        patch(role, Map.of("stage", "DISABLED"), "stage");
        expectDenied(read.get(), 200);
        patch(role, Map.of("stage", "GA"), "stage");
        read.get().statusCode(200);

        given().delete(role).then().statusCode(200).body("deleted", equalTo(true));
        expectDenied(read.get(), 200);
        given().urlEncodingEnabled(false).contentType("application/json").body(Map.of())
                .post(role + ":undelete").then().statusCode(200);
        read.get().statusCode(200);
    }

    @Test
    void projectRoleBoundOutsideItsProjectGrantsNothing() {
        String otherProject = project + "-other";
        String otherTopic = otherProject + "/topics/source";
        pubsub.createTopic(otherTopic);
        createRoleViaApi(project, "topicreader", List.of("pubsub.topics.get"));
        grant(otherProject, project + "/roles/topicreader", null);

        expectDenied(given().header("Authorization", credential).get("/v1/" + otherTopic).then(), 200);
        if (enforced()) {
            expectGrpcDenied(() -> PublisherGrpc.newBlockingStub(caller).withDeadlineAfter(5, TimeUnit.SECONDS)
                    .getTopic(GetTopicRequest.newBuilder().setTopic(otherTopic).build()));
        }
        given().urlEncodingEnabled(false).header("Authorization", credential).contentType("application/json")
                .body(Map.of("permissions", List.of("pubsub.topics.get")))
                .post("/v1/" + otherTopic + ":testIamPermissions")
                .then().statusCode(200).body("permissions", equalTo(enforced() ? List.of() : List.of("pubsub.topics.get")));
    }

    @Test
    void organizationRoleGrantsOnlyInProjectsRecordedUnderItsOrganization() {
        String organization = "organizations/" + Math.abs(UUID.randomUUID().getMostSignificantBits() % 1_000_000_000L);
        createRoleViaApi(organization, "topicreader", List.of("pubsub.topics.get"));
        String orgRole = organization + "/roles/topicreader";
        Map<String, Map<String, String>> parents = Map.of(
                "in", Map.of("type", "organization", "id", organization.substring("organizations/".length())),
                "other", Map.of("type", "organization", "id", "1"),
                "folder", Map.of("type", "folder", "id", organization.substring("organizations/".length())));
        for (String suffix : List.of("in", "other", "folder", "none")) {
            String id = projectId + "-" + suffix;
            Map<String, Object> body = parents.containsKey(suffix)
                    ? Map.of("projectId", id, "parent", parents.get(suffix)) : Map.of("projectId", id);
            given().contentType("application/json").body(body).post("/v1/projects").then().statusCode(200);
            pubsub.createTopic("projects/" + id + "/topics/source");
            grant("projects/" + id, orgRole, null);
        }

        given().header("Authorization", credential).get("/v1/projects/" + projectId + "-in/topics/source")
                .then().statusCode(200);
        for (String suffix : List.of("other", "folder", "none")) {
            expectDenied(given().header("Authorization", credential)
                    .get("/v1/projects/" + projectId + "-" + suffix + "/topics/source").then(), 200);
        }
    }

    @Test
    void organizationRoleManagementEvaluatesTheStoredOrganizationPolicy() {
        String organization = "organizations/" + Math.abs(UUID.randomUUID().getMostSignificantBits() % 1_000_000_000L);
        Map<String, Object> create = Map.of("roleId", "reader", "role", Map.of("title", "Reader"));
        expectDenied(given().header("Authorization", credential).contentType("application/json").body(create)
                .post("/v1/" + organization + "/roles").then(), 200);
        if (enforced()) {
            given().get("/v1/" + organization + "/roles/reader").then().statusCode(404);
        }

        // The mixin accepts organization policy writes only from callers that bypass evaluation.
        Policy policy = Policy.newBuilder().addBindings(Binding.newBuilder()
                .setRole("roles/iam.organizationRoleAdmin").addMembers(member)).build();
        IAMPolicyGrpc.newBlockingStub(channel).withDeadlineAfter(5, TimeUnit.SECONDS).setIamPolicy(
                SetIamPolicyRequest.newBuilder().setResource(organization).setPolicy(policy).build());
        if (enforced()) {
            given().header("Authorization", credential).contentType("application/json").body(create)
                    .post("/v1/" + organization + "/roles").then().statusCode(200);
        }
        given().header("Authorization", credential).get("/v1/" + organization + "/roles/reader")
                .then().statusCode(200).body("name", equalTo(organization + "/roles/reader"));
        expectGrpcStatusWhenEnforced(Status.Code.FAILED_PRECONDITION, () -> IAMPolicyGrpc.newBlockingStub(caller)
                .withDeadlineAfter(5, TimeUnit.SECONDS).getIamPolicy(GetIamPolicyRequest
                        .newBuilder().setResource(organization).build()));
    }

    @Test
    void unsupportedConditionOnAnApplicableCustomRoleIsRejected() {
        String topic = project + "/topics/source";
        pubsub.createTopic(topic);
        createRoleViaApi(project, "topicreader", List.of("pubsub.topics.get"));
        grant(project, project + "/roles/topicreader", "resource.name.matches('.*')");
        ValidatableResponse response = given().header("Authorization", credential).get("/v1/" + topic).then();
        if (enforced()) {
            response.statusCode(400).body("error.status", equalTo("INVALID_ARGUMENT"));
        } else {
            response.statusCode(200);
        }
    }

    private void createRoleViaApi(String parent, String roleId, List<String> permissions) {
        given().contentType("application/json")
                .body(Map.of("roleId", roleId, "role", Map.of("includedPermissions", permissions, "stage", "GA")))
                .post("/v1/" + parent + "/roles").then().statusCode(200);
    }

    private void patch(String role, Map<String, Object> body, String mask) {
        given().contentType("application/json").body(body).queryParam("updateMask", mask)
                .patch(role).then().statusCode(200);
    }

    private void grant(String resource, String role, String expression) {
        StoredPolicy policy = new StoredPolicy();
        if (expression == null) {
            policy.setBindings(List.of(Map.of("role", role, "members", List.of(member))));
        } else {
            policy.setVersion(3);
            policy.setBindings(List.of(Map.of("role", role, "members", List.of(member),
                    "condition", Map.of("title", "scope", "expression", expression))));
        }
        policies.setPolicy(resource, policy);
    }

    private void expectDenied(ValidatableResponse response, int disabledStatus) {
        if (enforced()) {
            response.statusCode(403).body("error.status", equalTo("PERMISSION_DENIED"));
        } else {
            response.statusCode(disabledStatus);
        }
    }

    private void expectGrpcDenied(Runnable call) {
        StatusRuntimeException error = assertThrows(StatusRuntimeException.class, call::run);
        assertEquals(Status.Code.PERMISSION_DENIED, error.getStatus().getCode());
    }

    private void expectGrpcStatusWhenEnforced(Status.Code code, Runnable call) {
        if (enforced()) {
            StatusRuntimeException error = assertThrows(StatusRuntimeException.class, call::run);
            assertEquals(code, error.getStatus().getCode());
        } else {
            call.run();
        }
    }
}
