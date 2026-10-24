package io.floci.gcp.test;

import com.google.api.client.googleapis.json.GoogleJsonResponseException;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.gson.GsonFactory;
import com.google.api.gax.core.NoCredentialsProvider;
import com.google.api.gax.grpc.GrpcTransportChannel;
import com.google.api.gax.rpc.FixedTransportChannelProvider;
import com.google.api.services.cloudresourcemanager.CloudResourceManager;
import com.google.api.services.cloudresourcemanager.model.Binding;
import com.google.api.services.cloudresourcemanager.model.Policy;
import com.google.api.services.cloudresourcemanager.model.Project;
import com.google.api.services.cloudresourcemanager.model.ResourceId;
import com.google.api.services.cloudresourcemanager.model.SetIamPolicyRequest;
import com.google.api.services.iam.v1.Iam;
import com.google.api.services.iam.v1.model.CreateRoleRequest;
import com.google.api.services.iam.v1.model.Role;
import com.google.api.services.iam.v1.model.UndeleteRoleRequest;
import com.google.api.services.pubsub.Pubsub;
import com.google.api.services.pubsub.model.TestIamPermissionsRequest;
import com.google.api.services.pubsub.model.Topic;
import com.google.cloud.pubsub.v1.TopicAdminClient;
import com.google.cloud.pubsub.v1.TopicAdminSettings;
import com.google.iam.v1.IAMPolicyGrpc;
import com.google.gson.JsonParser;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.grpc.Metadata;
import io.grpc.stub.MetadataUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Official IAM v1 REST client for project and organization custom roles, plus Pub/Sub REST and gRPC
 * clients exercising the permissions those roles grant through existing adapters.
 */
class IamCustomRoleIamEnforcementTest {

    private final boolean enforce = Boolean.parseBoolean(System.getenv("FLOCI_GCP_IAM_TEST_ENFORCEMENT"));
    private String project;
    private String member;
    private Iam admin;
    private Iam management;
    private CloudResourceManager resourceManager;
    private Pubsub setupPubsub;
    private Pubsub callerPubsub;
    private ManagedChannel anonymousChannel;
    private ManagedChannel callerChannel;
    private TopicAdminClient callerTopics;

    @BeforeEach
    void setUp() throws Exception {
        project = TestFixtures.uniqueName("iam-custom-role");
        String email = "caller@" + project + ".iam.gserviceaccount.com";
        member = "serviceAccount:" + email;
        String token = accessToken(email);
        admin = iam(null);
        management = iam(token);
        resourceManager = new CloudResourceManager.Builder(new NetHttpTransport(), GsonFactory.getDefaultInstance(),
                ignored -> {}).setRootUrl(TestFixtures.endpoint() + "/")
                .setApplicationName("floci-iam-custom-role-compat").build();
        setupPubsub = pubsub(null);
        callerPubsub = pubsub(token);
        URI endpoint = URI.create(TestFixtures.endpoint());
        anonymousChannel = ManagedChannelBuilder.forAddress(endpoint.getHost(), endpoint.getPort()).usePlaintext().build();
        Metadata headers = new Metadata();
        headers.put(Metadata.Key.of("authorization", Metadata.ASCII_STRING_MARSHALLER), "Bearer " + token);
        callerChannel = ManagedChannelBuilder.forAddress(endpoint.getHost(), endpoint.getPort()).usePlaintext()
                .intercept(MetadataUtils.newAttachHeadersInterceptor(headers)).build();
        callerTopics = TopicAdminClient.create(TopicAdminSettings.newBuilder()
                .setTransportChannelProvider(FixedTransportChannelProvider.create(GrpcTransportChannel.create(callerChannel)))
                .setCredentialsProvider(NoCredentialsProvider.create()).build());
    }

    @AfterEach
    void close() throws Exception {
        callerTopics.close();
        callerChannel.shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
        anonymousChannel.shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
    }

    @Test
    void officialIamClientManagesProjectRolesOnlyWithIamRolesPermissions() throws Exception {
        String parent = "projects/" + project;
        String name = parent + "/roles/reader";
        CreateRoleRequest create = new CreateRoleRequest().setRoleId("reader").setRole(new Role()
                .setTitle("Reader").setIncludedPermissions(List.of("pubsub.topics.get")).setStage("GA"));
        deniedRest(() -> management.projects().roles().create(parent, create).execute());
        if (enforce) {
            assertThat(admin.projects().roles().list(parent).execute().getRoles()).isNullOrEmpty();
            admin.projects().roles().create(parent, create).execute();
        }

        grantProject(project, "roles/iam.roleViewer");
        Role read = management.projects().roles().get(name).execute();
        assertThat(read.getIncludedPermissions()).containsExactly("pubsub.topics.get");
        assertThat(read.getStage()).isEqualTo("GA");
        Role basic = management.projects().roles().list(parent).execute().getRoles().getFirst();
        assertThat(basic.getName()).isEqualTo(name);
        assertThat(basic.getIncludedPermissions()).isNull();
        assertThat(management.projects().roles().list(parent).setView("FULL").execute().getRoles().getFirst()
                .getIncludedPermissions()).containsExactly("pubsub.topics.get");
        deniedRest(() -> management.projects().roles().patch(name, new Role().setTitle("Escalated"))
                .setUpdateMask("title").execute());
        if (enforce) {
            assertThat(admin.projects().roles().get(name).execute().getTitle()).isEqualTo("Reader");
            assertThat(admin.projects().roles().get(name).execute().getEtag()).isEqualTo(read.getEtag());
        }

        grantProject(project, "roles/iam.roleAdmin");
        Role current = management.projects().roles().get(name).execute();
        Role patched = management.projects().roles().patch(name, new Role().setDescription("patched")
                .setEtag(current.getEtag())).setUpdateMask("description").execute();
        assertThat(patched.getDescription()).isEqualTo("patched");
        Role deleted = management.projects().roles().delete(name).setEtag(patched.getEtag()).execute();
        assertThat(deleted.getDeleted()).isTrue();
        assertThat(management.projects().roles().list(parent).execute().getRoles()).isNullOrEmpty();
        assertThat(management.projects().roles().list(parent).setShowDeleted(true).execute().getRoles())
                .extracting(Role::getName).containsExactly(name);
        Role restored = management.projects().roles().undelete(name,
                new UndeleteRoleRequest().setEtag(deleted.getEtag())).execute();
        assertThat(restored.getDeleted()).isNull();
        Role created = management.projects().roles().create(parent, new CreateRoleRequest().setRoleId("writer")
                .setRole(new Role().setIncludedPermissions(List.of("pubsub.topics.delete")))).execute();
        assertThat(created.getName()).isEqualTo(parent + "/roles/writer");
        assertThat(created.getStage()).isNull();
    }

    @Test
    void apiCreatedRoleGrantsExactlyItsPermissionsOverOfficialRestAndGrpcClients() throws Exception {
        String topic = "projects/" + project + "/topics/source";
        setupPubsub.projects().topics().create(topic, new Topic()).execute();
        String role = createProjectRole(project, "topicreader", "pubsub.topics.get");
        grantProject(project, role);

        assertThat(callerPubsub.projects().topics().get(topic).execute().getName()).isEqualTo(topic);
        assertThat(callerTopics.getTopic(topic).getName()).isEqualTo(topic);
        List<String> requested = List.of("pubsub.topics.get", "pubsub.topics.delete");
        assertThat(callerPubsub.projects().topics().testIamPermissions(topic,
                new TestIamPermissionsRequest().setPermissions(requested)).execute().getPermissions())
                .containsExactlyElementsOf(enforce ? List.of("pubsub.topics.get") : requested);
        if (enforce) {
            deniedRest(() -> callerPubsub.projects().topics().delete(topic).execute());
            assertThatThrownBy(() -> callerTopics.deleteTopic(topic)).hasMessageContaining("PERMISSION_DENIED");
            assertThat(setupPubsub.projects().topics().get(topic).execute().getName()).isEqualTo(topic);
        }

        Role current = admin.projects().roles().get(role).execute();
        Role edited = admin.projects().roles().patch(role, new Role().setIncludedPermissions(List.of("pubsub.topics.list"))
                .setEtag(current.getEtag())).setUpdateMask("includedPermissions").execute();
        deniedRest(() -> callerPubsub.projects().topics().get(topic).execute());
        Role disabled = admin.projects().roles().patch(role, new Role()
                .setIncludedPermissions(List.of("pubsub.topics.get")).setStage("DISABLED").setEtag(edited.getEtag()))
                .setUpdateMask("includedPermissions,stage").execute();
        deniedRest(() -> callerPubsub.projects().topics().get(topic).execute());
        Role enabled = admin.projects().roles().patch(role, new Role().setStage("GA").setEtag(disabled.getEtag()))
                .setUpdateMask("stage").execute();
        assertThat(callerTopics.getTopic(topic).getName()).isEqualTo(topic);
        Role deleted = admin.projects().roles().delete(role).setEtag(enabled.getEtag()).execute();
        if (enforce) {
            assertThatThrownBy(() -> callerTopics.getTopic(topic)).hasMessageContaining("PERMISSION_DENIED");
        }
        admin.projects().roles().undelete(role, new UndeleteRoleRequest().setEtag(deleted.getEtag())).execute();
        assertThat(callerPubsub.projects().topics().get(topic).execute().getName()).isEqualTo(topic);
    }

    @Test
    void customRolesDoNotCrossProjectOrOrganizationBoundaries() throws Exception {
        String otherProject = project + "-x";
        String otherTopic = "projects/" + otherProject + "/topics/source";
        setupPubsub.projects().topics().create(otherTopic, new Topic()).execute();
        grantProject(otherProject, createProjectRole(project, "topicreader", "pubsub.topics.get"));
        deniedRest(() -> callerPubsub.projects().topics().get(otherTopic).execute());
        if (enforce) {
            assertThatThrownBy(() -> callerTopics.getTopic(otherTopic)).hasMessageContaining("PERMISSION_DENIED");
        }

        String organization = organizationId();
        Role orgRole = admin.organizations().roles().create("organizations/" + organization, new CreateRoleRequest()
                .setRoleId("topicreader").setRole(new Role().setIncludedPermissions(List.of("pubsub.topics.get"))))
                .execute();
        String inOrg = project + "-in";
        String outsideOrg = project + "-out";
        resourceManager.projects().create(new Project().setProjectId(inOrg)
                .setParent(new ResourceId().setType("organization").setId(organization))).execute();
        resourceManager.projects().create(new Project().setProjectId(outsideOrg)
                .setParent(new ResourceId().setType("organization").setId(organizationId()))).execute();
        for (String id : List.of(inOrg, outsideOrg)) {
            setupPubsub.projects().topics().create("projects/" + id + "/topics/source", new Topic()).execute();
            grantProject(id, orgRole.getName());
        }
        assertThat(callerTopics.getTopic("projects/" + inOrg + "/topics/source").getName())
                .isEqualTo("projects/" + inOrg + "/topics/source");
        deniedRest(() -> callerPubsub.projects().topics().get("projects/" + outsideOrg + "/topics/source").execute());
    }

    @Test
    void organizationRoleManagementUsesTheOrganizationPolicy() throws Exception {
        String parent = "organizations/" + organizationId();
        CreateRoleRequest create = new CreateRoleRequest().setRoleId("reader")
                .setRole(new Role().setIncludedPermissions(List.of("pubsub.topics.get")));
        deniedRest(() -> management.organizations().roles().create(parent, create).execute());
        if (enforce) {
            assertThat(admin.organizations().roles().list(parent).execute().getRoles()).isNullOrEmpty();
        }
        // Only callers that bypass evaluation can store an organization policy through the mixin. The
        // protobuf policy types collide with the Resource Manager REST policy types imported above.
        IAMPolicyGrpc.newBlockingStub(anonymousChannel).withDeadlineAfter(5, TimeUnit.SECONDS).setIamPolicy(
                com.google.iam.v1.SetIamPolicyRequest.newBuilder().setResource(parent)
                        .setPolicy(com.google.iam.v1.Policy.newBuilder().addBindings(com.google.iam.v1.Binding
                                .newBuilder().setRole("roles/iam.organizationRoleAdmin").addMembers(member)))
                        .build());
        if (enforce) {
            management.organizations().roles().create(parent, create).execute();
        }
        String name = parent + "/roles/reader";
        Role role = management.organizations().roles().get(name).execute();
        assertThat(role.getIncludedPermissions()).containsExactly("pubsub.topics.get");
        assertThat(management.organizations().roles().list(parent).execute().getRoles())
                .extracting(Role::getName).containsExactly(name);
        Role deleted = management.organizations().roles().delete(name).execute();
        assertThat(deleted.getDeleted()).isTrue();
        assertThat(management.organizations().roles().undelete(name, new UndeleteRoleRequest()).execute()
                .getDeleted()).isNull();
    }

    private String createProjectRole(String projectId, String roleId, String permission) throws IOException {
        return admin.projects().roles().create("projects/" + projectId, new CreateRoleRequest().setRoleId(roleId)
                .setRole(new Role().setIncludedPermissions(List.of(permission)))).execute().getName();
    }

    private void grantProject(String projectId, String role) throws IOException {
        resourceManager.projects().setIamPolicy(projectId, new SetIamPolicyRequest().setPolicy(new Policy()
                .setBindings(List.of(new Binding().setRole(role).setMembers(List.of(member)))))).execute();
    }

    private void deniedRest(IoCall call) throws Exception {
        if (enforce) {
            assertThatThrownBy(call::run).isInstanceOfSatisfying(GoogleJsonResponseException.class, error -> {
                assertThat(error.getStatusCode()).isEqualTo(403);
                assertThat(error.getDetails().get("status")).isEqualTo("PERMISSION_DENIED");
            });
        } else {
            call.run();
        }
    }

    @FunctionalInterface
    private interface IoCall {
        void run() throws IOException;
    }

    private static String organizationId() {
        return Long.toString(Math.abs(UUID.randomUUID().getMostSignificantBits() % 1_000_000_000_000L) + 1);
    }

    private Iam iam(String bearer) {
        return new Iam.Builder(new NetHttpTransport(), GsonFactory.getDefaultInstance(), request -> {
            if (bearer != null) {
                request.getHeaders().setAuthorization("Bearer " + bearer);
            }
        }).setRootUrl(TestFixtures.endpoint() + "/").setApplicationName("floci-iam-custom-role-compat").build();
    }

    private Pubsub pubsub(String bearer) {
        return new Pubsub.Builder(new NetHttpTransport(), GsonFactory.getDefaultInstance(), request -> {
            if (bearer != null) {
                request.getHeaders().setAuthorization("Bearer " + bearer);
            }
        }).setRootUrl(TestFixtures.endpoint() + "/").setApplicationName("floci-iam-custom-role-compat").build();
    }

    private static String accessToken(String email) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create(TestFixtures.endpoint()
                        + "/v1/projects/-/serviceAccounts/" + email + ":generateAccessToken"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(
                        "{\"scope\":[\"https://www.googleapis.com/auth/cloud-platform\"]}"))
                .build();
        try (HttpClient http = HttpClient.newHttpClient()) {
            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
            assertThat(response.statusCode()).as(response.body()).isEqualTo(200);
            return JsonParser.parseString(response.body()).getAsJsonObject().get("accessToken").getAsString();
        }
    }
}
