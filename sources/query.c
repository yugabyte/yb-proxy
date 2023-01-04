
/*
 * Odyssey.
 *
 * Scalable PostgreSQL connection pooler.
 */

#include <kiwi.h>
#include <machinarium.h>
#include <odyssey.h>

machine_msg_t *od_query_do(od_server_t *server, char *context, char *query,
			   char *param)
{
	od_instance_t *instance = server->global->instance;
	od_debug(&instance->logger, context, server->client, server, "%s",
		 query);

	if (od_backend_query_send(server, context, query, param,
				  strlen(query) + 1) == NOT_OK_RESPONSE) {
		return NULL;
	}
	machine_msg_t *ret_msg = NULL;
	machine_msg_t *msg;

	/* wait for response */
	int has_result = 0;
	while (1) {
		msg = od_read(&server->io, UINT32_MAX);
		if (msg == NULL) {
			if (!machine_timedout()) {
				od_error(&instance->logger, context,
					 server->client, server,
					 "read error: %s",
					 od_io_error(&server->io));
			}
			return NULL;
		}

		int save_msg = 0;
		kiwi_be_type_t type;
		type = *(char *)machine_msg_data(msg);

		od_debug(&instance->logger, context, server->client, server,
			 "%s", kiwi_be_type_to_string(type));

		switch (type) {
		case KIWI_BE_ERROR_RESPONSE:
			od_backend_error(server, context, machine_msg_data(msg),
					 machine_msg_size(msg));
			goto error;
		case KIWI_BE_ROW_DESCRIPTION:
			break;
		case KIWI_BE_DATA_ROW: {
			if (has_result) {
				goto error;
			}

			ret_msg = msg;
			has_result = 1;
			save_msg = 1;
			break;
		}
		case KIWI_BE_READY_FOR_QUERY:
			od_backend_ready(server, machine_msg_data(msg),
					 machine_msg_size(msg));

			machine_msg_free(msg);
			return ret_msg;
		default:
			break;
		}

		if (!save_msg) {
			machine_msg_free(msg);
		}
	}
	return ret_msg;
error:
	machine_msg_free(msg);
	return NULL;
}

int yb_query_passthrough(od_server_t *server, od_client_t *client)
{	
	od_instance_t *instance = server->global->instance;
	int rc =0 ;
	machine_msg_t *ret_msg = NULL;
	machine_msg_t *msg;
	char peer[128];
	od_getpeername(client->io.io, peer, sizeof(peer), 1, 0);
	
	msg = kiwi_fe_write_authentication(NULL,
			client->startup.user.value , 
			client->startup.database.value,
			peer );

   	rc = od_write(&server->io, msg);
	if(rc == -1 )
	{
		od_log(&instance->logger, "auth", client, server,"Unable to send packet");
		return -1;
	}	
	
	od_log(&instance->logger, "auth", client, server,"Sent the Auth request");

	/* wait for response */
	while(1){
		od_log(&instance->logger, "Pass through", server->client, server," Waiting for the msg");
		msg = od_read(&server->io, UINT32_MAX);
		if (msg == NULL) {
			if (!machine_timedout()) {
				od_error(&instance->logger, "Pass through",
					 server->client, server,
					 "read error from server: %s",
					 od_io_error(&server->io));
					 return -1;
			}
		}
		int save_msg = 0;
		kiwi_be_type_t type;
		type = *(char *)machine_msg_data(msg);

		od_log(&instance->logger, "Pass through", server->client, server,
			 "%s", kiwi_be_type_to_string(type));
		
		uint32_t auth_type;

		/* Check for the authenticationOK message	*/	
		if(type == KIWI_BE_AUTHENTICATION){
			char salt[4];
			char *auth_data = NULL;
			size_t auth_data_size = 0;
			int rc;
			rc = kiwi_fe_read_auth(machine_msg_data(msg), machine_msg_size(msg),
					       &auth_type, salt, &auth_data, &auth_data_size);
			if (rc == -1) {
				od_error(&instance->logger, "Pass through", NULL, server,
					 "failed to parse authentication message");
			}else {
				if(auth_type==0)
				{
					od_log(&instance->logger, "Pass through", server->client, server, "Authenticated");
					return 0;
				}else if(auth_type == 13) /* 13 for auth not ok */
				{
					od_log(&instance->logger, "Pass through", server->client, server, "Authentication Failed");
					msg = od_read(&server->io, UINT32_MAX);
					if (msg == NULL) {
						if (!machine_timedout()) {
							od_error(&instance->logger, "Pass through",
								 server->client, server,
								 "read error from server: %s",
								 od_io_error(&server->io));
								 return -1;
						}
					}

					// if( *(char *)machine_msg_data(msg) == KIWI_BE_ERROR_RESPONSE)
					//  	*(char *)machine_msg_data(msg) = '';	
					/* Forward the error */
					rc = od_write(&client->io, msg);

					return -1;	
				}
			}
		}else 
			continue;
	
		/* Forward the message to the client */
	if (msg == NULL)
		return -1;

	rc = od_write(&client->io, msg);
	if (rc == -1) {
		od_error(&instance->logger, "auth passthrough", client, NULL,
			 "write error in middleware: %s", od_io_error(&client->io));
		goto client_failed;;
	}else
		od_log(&instance->logger, "auth passthrough", client, NULL, " Auth request sent");
	
		/* wait for password response */
	while (1) {
		msg = od_read(&client->io, UINT32_MAX);
		if (msg == NULL) {
			od_error(&instance->logger, "auth passthrough", client, NULL,
				 "read error in middleware: %s", od_io_error(&client->io));
			goto client_failed;
		}
		kiwi_fe_type_t type = *(char *)machine_msg_data(msg);
		od_debug(&instance->logger, "auth passthrough ", client, NULL, "%s",
			 kiwi_fe_type_to_string(type));
		if (type == KIWI_FE_PASSWORD_MESSAGE)	/* Change this */
			break;
		machine_msg_free(msg);
	}

	rc = od_write(&server->io, msg);
	if(rc == -1 ){
		od_log(&instance->logger, "auth passthrough", client, server,"Unable to send packet");
		return -1;
	}
	else
		od_log(&instance->logger, "auth passthrough", client, server,"Sent the Auth Packet to the server");
	}

success:
	return 0 ;
	
	/* 
		In case the client connection fails 
		i.e. od_read or od_write on client socket fails and 
		database is expecting a packet from client.
		SEND a Packet that is NOT EXPECTED by the database; so that
		the authentication fails from the database end and AUTHFAIL 
		is returned; followed by a `READYFORQUERY` packet.
	*/
client_failed:
	{
		/* Send a dummy packet, to stop the OD read */
		od_log(&instance->logger, "auth passthrough", client, server,"Sent the Auth Packet to the server");
		msg = kiwi_fe_write_password(NULL, NULL, 0 );
		if(msg == NULL)
		{
			printf("Unable to write the packet !! \n\n");
		}

		if(od_write(&server->io,msg)== -1)
		{
			/* Log the error */
			od_error(&instance->logger, "auth passthrough", NULL, server,
			 "write error in sever: %s", od_io_error(&server->io));
		}
		printf("Sent a packet to terminate the authentication passthrough at the database side \n\n");
		return -1;
	}

server_failed:
	{
	/* Do nothing as of now */	
	}
	
}



__attribute__((hot)) int od_query_format(char *format_pos, char *format_end,
					 kiwi_var_t *user, char *peer,
					 char *output, int output_len)
{
	char *dst_pos = output;
	char *dst_end = output + output_len;
	while (format_pos < format_end) {
		if (*format_pos == '%') {
			format_pos++;
			if (od_unlikely(format_pos == format_end))
				break;
			int len;
			switch (*format_pos) {
			case 'u':
				len = od_snprintf(dst_pos, dst_end - dst_pos,
						  "%s", user->value);
				dst_pos += len;
				break;
			case 'h':
				len = od_snprintf(dst_pos, dst_end - dst_pos,
						  "%s", peer);
				dst_pos += len;
				break;
			default:
				if (od_unlikely((dst_end - dst_pos) < 2))
					break;
				dst_pos[0] = '%';
				dst_pos[1] = *format_pos;
				dst_pos += 2;
				break;
			}
		} else {
			if (od_unlikely((dst_end - dst_pos) < 1))
				break;
			dst_pos[0] = *format_pos;
			dst_pos += 1;
		}
		format_pos++;
	}
	if (od_unlikely((dst_end - dst_pos) < 1))
		return -1;
	dst_pos[0] = 0;
	dst_pos++;
	return dst_pos - output;
}
