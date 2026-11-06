// lrnet: two-player rooms for Lost Reavers offline (see lrnet.c).
#pragma once
#ifdef __cplusplus
extern "C" {
#endif
extern unsigned int lr_code_off;                         // plugin: where the console loaded the game's code
void lr_set_server(unsigned int ip, unsigned int port); // default 127.0.0.1:8765
int lr_Process(unsigned int self);
int lr_SendTo(unsigned int self, const unsigned char *buf, int len, int *sent, unsigned int pid);
int lr_InternalSend(unsigned int self, unsigned int user, unsigned int pid, const unsigned char *data, unsigned int len);
int lr_CreateStart(unsigned int self);
int lr_FindStart(unsigned int self);
int lr_LoginStart(unsigned int self);
int lr_Logout(unsigned int self, unsigned int ctx, unsigned int gid);
int lr_OpenStart(unsigned int self);
int lr_UpdateAttrStart(unsigned int self);
int lr_CloseStart(unsigned int self);
#ifdef __cplusplus
}
#endif
