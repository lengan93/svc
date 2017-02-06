#include <libssh/libssh.h>
#include <stdlib.h>
#include <stdio.h> 
#include <cstring>
#include <sys/stat.h>
//using namespace std;

int scp_helloworld(ssh_session session, ssh_scp scp)
{
  int rc;
  const char *helloworld = "Hello, world!\n";
  int length = strlen(helloworld);
  rc = ssh_scp_push_directory(scp, "helloworld", S_IRWXU);
  if (rc != SSH_OK)
  {
    fprintf(stderr, "Can't create remote directory: %s\n",
            ssh_get_error(session));
    return rc;
  }
  rc = ssh_scp_push_file
    (scp, "helloworld.txt", length, S_IRUSR |  S_IWUSR);
  if (rc != SSH_OK)
  {
    fprintf(stderr, "Can't open remote file: %s\n",
            ssh_get_error(session));
    return rc;
  }
  rc = ssh_scp_write(scp, helloworld, length);
  rc = ssh_scp_write(scp, helloworld, length);
  if (rc != SSH_OK)
  {
    fprintf(stderr, "Can't write to remote file: %s\n",
            ssh_get_error(session));
    return rc;
  }
  return SSH_OK;
}

int scp_write(ssh_session session) {
  ssh_scp scp;
  int rc;
  scp = ssh_scp_new
    (session, SSH_SCP_WRITE | SSH_SCP_RECURSIVE, ".");
  if (scp == NULL)
  {
    fprintf(stderr, "Error allocating scp session: %s\n",
            ssh_get_error(session));
    return SSH_ERROR;
  }
  rc = ssh_scp_init(scp);
  if (rc != SSH_OK)
  {
    fprintf(stderr, "Error initializing scp session: %s\n",
            ssh_get_error(session));
    ssh_scp_free(scp);
    return rc;
  }

  scp_helloworld(session, scp);

  ssh_scp_close(scp);
  ssh_scp_free(scp);
  return SSH_OK;
}


int main()
{
  ssh_session my_ssh_session;
  int rc;
  char *username;
  char *password;
  // Open session and set options
  my_ssh_session = ssh_new();
  if (my_ssh_session == NULL)
    exit(-1);
  ssh_options_set(my_ssh_session, SSH_OPTIONS_HOST, "149.56.142.13");
  // Connect to server
  rc = ssh_connect(my_ssh_session);
  if (rc != SSH_OK)
  {
    fprintf(stderr, "Error connecting to localhost: %s\n",
            ssh_get_error(my_ssh_session));
    ssh_free(my_ssh_session);
    exit(-1);
  }
  // Verify the server's identity
  // For the source code of verify_knowhost(), check previous example
  // if (verify_knownhost(my_ssh_session) < 0)
  // {
  //   ssh_disconnect(my_ssh_session);
  //   ssh_free(my_ssh_session);
  //   exit(-1);
  // }
  // Authenticate ourselves
  username = "nganle";
  password = "vinamilk";
  rc = ssh_userauth_password(my_ssh_session, username, password);
  if (rc != SSH_AUTH_SUCCESS)
  {
    fprintf(stderr, "Error authenticating with password: %s\n",
            ssh_get_error(my_ssh_session));
    ssh_disconnect(my_ssh_session);
    ssh_free(my_ssh_session);
    exit(-1);
  }
  //...
  scp_write(my_ssh_session);

  ssh_disconnect(my_ssh_session);
  ssh_free(my_ssh_session);
}

