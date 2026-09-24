#include <openssl/ssl.h>
#include <openssl/err.h>

int main()
{
	SSL_library_init();
	SSL_CTX *ctx = SSL_CTX_new(SSLv23_method());
	if(ctx)
		SSL_CTX_free(ctx);
	return ctx ? 0 : 1;
}
