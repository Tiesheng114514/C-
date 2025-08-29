#include <openssl/applink.c>
#include "enc_dec.h"
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#pragma comment(lib,"C:\\OpenSSL64\\lib\\VC\\x64\\MT\\libcrypto.lib")
#pragma comment(lib,"C:\\OpenSSL64\\lib\\VC\\x64\\MT\\libssl.lib")

// 函数声明
void file_hash_tool();
void file_hash_compare();
void show_tutorial();
void encrypt_file_aes();
void decrypt_file_aes();
void encrypt_file_rsa_aes();
void decrypt_file_rsa_aes();
void init_one_on_one_chat();
void init_group_chat();
void chat_interface(int is_group);
void clear_input_buffer();
char* base64_encode(const unsigned char* input, size_t length);
unsigned char* base64_decode(const char* input, size_t* output_length);

// 全局状态变量
unsigned char* rsa_public_key = NULL;
unsigned char* rsa_private_key = NULL;
unsigned char* partner_public_key = NULL;
unsigned char* group_aes_key = NULL;
long group_aes_key_size = 0;
int chat_role = 0; // 0:未设置, 1:发送方, 2:接收方, 3:群主, 4:群成员

// 清除输入缓冲区
void clear_input_buffer() {
  int c;
  while ((c = getchar()) != '\n' && c != EOF);
}

// Base64编码
char* base64_encode(const unsigned char* input, size_t length) {
  BIO* bmem = BIO_new(BIO_s_mem());
  BIO* b64 = BIO_new(BIO_f_base64());
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  b64 = BIO_push(b64, bmem);

  BIO_write(b64, input, (int)length);
  BIO_flush(b64);

  BUF_MEM* bptr;
  BIO_get_mem_ptr(b64, &bptr);

  char* buff = (char*)malloc(bptr->length + 1);
  memcpy(buff, bptr->data, bptr->length);
  buff[bptr->length] = 0;

  BIO_free_all(b64);
  return buff;
}

// Base64解码
unsigned char* base64_decode(const char* input, size_t* output_length) {
  BIO* b64 = BIO_new(BIO_f_base64());
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

  size_t len = strlen(input);
  BIO* bmem = BIO_new_mem_buf(input, (int)len);
  bmem = BIO_push(b64, bmem);

  unsigned char* buffer = (unsigned char*)malloc(len);
  *output_length = BIO_read(bmem, buffer, (int)len);
  buffer[*output_length] = '\0';

  BIO_free_all(bmem);
  return buffer;
}

// 文件哈希计算
void file_hash_tool() {
  char path[256];
  printf("请输入文件路径: ");
  scanf_s("%255s", path, (unsigned)_countof(path));
  clear_input_buffer();

  long size;
  unsigned char* data = file_read(path, &size);
  if (!data) {
    printf("文件读取失败\n");
    return;
  }

  unsigned char hash[32];
  unsigned int hash_len;
  SHA_256(data, size, hash, &hash_len);

  printf("\n文件哈希值(SHA-256):\n");
  for (int i = 0; i < 32; i++) {
    printf("%02x", hash[i]);
  }
  printf("\n");

  free(data);
}

// 文件哈希比较
void file_hash_compare() {
  char path1[256], path2[256];
  printf("请输入第一个文件路径: ");
  scanf_s("%255s", path1, (unsigned)_countof(path1));
  clear_input_buffer();

  printf("请输入第二个文件路径: ");
  scanf_s("%255s", path2, (unsigned)_countof(path2));
  clear_input_buffer();

  // 计算第一个文件哈希
  long size1;
  unsigned char* data1 = file_read(path1, &size1);
  if (!data1) {
    printf("第一个文件读取失败\n");
    return;
  }
  unsigned char hash1[32];
  unsigned int hash_len1;
  SHA_256(data1, size1, hash1, &hash_len1);
  free(data1);

  // 计算第二个文件哈希
  long size2;
  unsigned char* data2 = file_read(path2, &size2);
  if (!data2) {
    printf("第二个文件读取失败\n");
    return;
  }
  unsigned char hash2[32];
  unsigned int hash_len2;
  SHA_256(data2, size2, hash2, &hash_len2);
  free(data2);

  // 比较哈希值
  int match = 1;
  for (int i = 0; i < 32; i++) {
    if (hash1[i] != hash2[i]) {
      match = 0;
      break;
    }
  }

  printf("\n文件1哈希值: ");
  for (int i = 0; i < 32; i++) printf("%02x", hash1[i]);
  printf("\n文件2哈希值: ");
  for (int i = 0; i < 32; i++) printf("%02x", hash2[i]);
  printf("\n比较结果: %s\n", match ? "相同" : "不同");
}

// 使用教程
void show_tutorial() {
  printf("\n==================================================\n");
  printf("使用教程\n");
  printf("==================================================\n");
  printf("1. 文件加密:\n");
  printf("   - AES加密: 使用AES-256算法加密文件，需要设置密码。加密速度快，适合大文件\n");
  printf("   - RSA+AES加密: 结合RSA和AES的优点，先用RSA加密随机生成的AES密钥，再用AES加密文件\n");
  printf("\n2. 文件哈希工具:\n");
  printf("   - 文件哈希计算: 计算文件的SHA-256哈希值，用于验证文件完整性\n");
  printf("   - 文件哈希比较: 比较两个文件的哈希值，判断它们是否相同\n");
  printf("\n3. 加密聊天:\n");
  printf("   - 一对一安全通信: 使用RSA非对称加密保护聊天内容\n");
  printf("   - 群组加密聊天: 使用AES对称密钥进行群组加密通信\n");
  printf("\n4. 文件解密:\n");
  printf("   - AES解密: 使用加密时设置的密码解密AES加密的文件\n");
  printf("   - RSA+AES解密: 使用私钥解密AES密钥，然后用该密钥解密文件\n");
  printf("\n5. 操作说明:\n");
  printf("   - 加密文件时会生成加密后的新文件，原始文件不会被修改\n");
  printf("   - 密钥和加密数据会以Base64格式显示，便于复制和传输\n");
  printf("   - RSA密钥对可以重复使用，AES密钥每次加密都会随机生成\n");
  printf("   - 哈希值用于验证文件完整性，相同内容的文件哈希值一定相同\n");
  printf("   - 在聊天功能中，输入/exit可以退出聊天\n");
  printf("==================================================\n\n");
}

// AES文件加密
void encrypt_file_aes() {
  char path[256];
  printf("请输入文件路径: ");
  scanf_s("%255s", path, (unsigned)_countof(path));
  clear_input_buffer();

  char key[256];
  printf("请输入加密密码: ");
  scanf_s("%255s", key, (unsigned)_countof(key));
  clear_input_buffer();

  long size;
  unsigned char* data = file_read(path, &size);
  if (!data) {
    printf("文件读取失败\n");
    return;
  }

  long mi_size;
  unsigned char* enc_data = enc_AES(data, &size, key, &mi_size);
  if (!enc_data) {
    printf("加密失败\n");
    free(data);
    return;
  }

  char out_path[256];
  sprintf_s(out_path, sizeof(out_path), "%s.aes", path);
  file_write(out_path, enc_data, mi_size);
  printf("文件已加密保存至: %s\n", out_path);

  free(data);
  free(enc_data);
}

// AES文件解密
void decrypt_file_aes() {
  char path[256];
  printf("请输入加密文件路径: ");
  scanf_s("%255s", path, (unsigned)_countof(path));
  clear_input_buffer();

  char key[256];
  printf("请输入解密密码: ");
  scanf_s("%255s", key, (unsigned)_countof(key));
  clear_input_buffer();

  long size;
  unsigned char* data = file_read(path, &size);
  if (!data) {
    printf("文件读取失败\n");
    return;
  }

  long ming_size;
  unsigned char* dec_data = dec_AES(data, &size, key, &ming_size);
  if (!dec_data) {
    printf("解密失败\n");
    free(data);
    return;
  }

  char out_path[256];
  sprintf_s(out_path, sizeof(out_path), "%s.dec", path);
  file_write(out_path, dec_data, ming_size);
  printf("文件已解密保存至: %s\n", out_path);

  free(data);
  free(dec_data);
}

// RSA+AES文件加密
void encrypt_file_rsa_aes() {
  // 定义文件路径缓冲区，最大长度为255字符（预留1位给空字符）
  char path[256];
  // 提示用户输入文件路径
  printf("请输入文件路径: ");
  // 安全读取用户输入，限制最大长度为255，防止缓冲区溢出
  scanf_s("%255s", path, (unsigned)_countof(path));
  // 清空输入缓冲区，避免残留字符影响后续输入
  clear_input_buffer();

  // 准备接收公钥的缓冲区，大小为4096字节（足够存储PEM格式的公钥）
  char public_key[4096] = { 0 };
  // 临时存储每行输入的缓冲区
  char line[256];
  // 缓冲区索引（未实际使用，可忽略）
  int idx = 0;

  // 提示用户粘贴公钥
  printf("请粘贴接收方的RSA公钥(以空行结束):\n");
  // 逐行读取用户输入，直到遇到空行（仅含换行符）
  while (fgets(line, sizeof(line), stdin)) {
    // 检测到空行时停止读取
    if (line[0] == '\n') break;
    // 将每行内容追加到公钥缓冲区，使用安全字符串拼接函数
    strcat_s(public_key, sizeof(public_key), line);
  }

  // 生成256位（32字节）AES密钥
  unsigned char aes_key[32];
  // 使用OpenSSL的随机数生成器生成密码学安全的随机密钥
  // RAND_bytes()返回1成功，0失败（此时应处理错误）
  RAND_bytes(aes_key, 32);
  // 记录密钥长度（32字节）
  long aes_key_size = 32;

  // 使用RSA公钥加密AES密钥
  long encrypted_key_size;
  // 调用自定义RSA加密函数，返回动态分配的加密后数据指针
  unsigned char* encrypted_aes_key = enc_RSA(aes_key, &aes_key_size, (unsigned char*)public_key, &encrypted_key_size);

  // 检查加密是否成功
  if (!encrypted_aes_key) {
    printf("RSA加密失败\n");
    return;  // 失败时直接返回
  }

  // 将加密后的二进制密钥转换为Base64字符串以便安全传输/显示
  char* encrypted_key_base64 = base64_encode(encrypted_aes_key, encrypted_key_size);
  if (!encrypted_key_base64) {
    printf("Base64编码失败\n");
    // 释放已分配的内存后返回
    free(encrypted_aes_key);
    return;
  }

  // 读取原始文件内容
  long file_size;
  // 调用自定义文件读取函数，返回动态分配的文件数据指针
  unsigned char* file_data = file_read(path, &file_size);
  if (!file_data) {
    printf("文件读取失败\n");
    free(encrypted_aes_key);
    free(encrypted_key_base64);
    return;
  }

  // 使用AES密钥加密文件内容
  long encrypted_size;
  // 调用自定义AES加密函数，返回动态分配的加密数据指针
  unsigned char* encrypted_data = enc_AES(file_data, &file_size, (char*)aes_key, &encrypted_size);

  if (!encrypted_data) {
    printf("AES加密失败\n");
    // 释放所有已分配的资源
    free(file_data);
    free(encrypted_aes_key);
    free(encrypted_key_base64);
    return;
  }

  // 生成输出文件路径（原路径追加后缀）
  char out_path[256];
  sprintf_s(out_path, sizeof(out_path), "%s.rsa.enc", path);

  // 将加密后的数据写入文件
  file_write(out_path, encrypted_data, encrypted_size);

  // 输出成功信息及Base64编码的加密密钥
  printf("\n加密文件已保存: %s\n", out_path);
  printf("加密后的AES密钥(Base64):\n%s\n", encrypted_key_base64);

  // 释放所有动态分配的内存
  free(file_data);
  free(encrypted_data);
  free(encrypted_aes_key);
  free(encrypted_key_base64);
}

// RSA+AES文件解密
void decrypt_file_rsa_aes() {

  RSA_key(&rsa_public_key, &rsa_private_key);

  printf("\n您的RSA公钥:\n%s\n", rsa_public_key);
  printf("您的RSA私钥(请妥善保存):\n%s\n", rsa_private_key);

  // 定义加密文件路径缓冲区
  char path[256];
  printf("请输入加密文件路径: ");
  scanf_s("%255s", path, (unsigned)_countof(path));
  clear_input_buffer();


  // 读取Base64格式的加密AES密钥
  printf("请粘贴加密的AES密钥(Base64):\n");
  char encrypted_key_base64[4096] = { 0 };
  fgets(encrypted_key_base64, sizeof(encrypted_key_base64), stdin);
  // 移除末尾换行符（fgets会保留换行符）
  encrypted_key_base64[strcspn(encrypted_key_base64, "\n")] = 0;

  // 解码Base64得到二进制加密密钥
  size_t encrypted_key_size;
  unsigned char* encrypted_key = base64_decode(encrypted_key_base64, &encrypted_key_size);
  if (!encrypted_key) {
    printf("Base64解码失败\n");
    return;
  }

  // 使用RSA私钥解密AES密钥
  long decrypted_key_size;
  // 注意：dec_RSA的第四个参数应为私钥，但原型中误写了public_key，实际实现应修正
  unsigned char* decrypted_aes_key = dec_RSA(encrypted_key, (long*)&encrypted_key_size, (unsigned char*)rsa_private_key, &decrypted_key_size);

  // 立即释放加密密钥缓冲区（已不再需要）
  free(encrypted_key);

  // 验证解密结果：密钥应为256位（32字节）
  if (!decrypted_aes_key || decrypted_key_size != 32) {
    printf("AES密钥解密失败\n");
    return;
  }

  // 读取加密文件内容
  long file_size;
  unsigned char* encrypted_data = file_read(path, &file_size);
  if (!encrypted_data) {
    printf("文件读取失败\n");
    free(decrypted_aes_key);
    return;
  }

  // 使用解密出的AES密钥解密文件内容
  long decrypted_size;
  unsigned char* decrypted_data = dec_AES(encrypted_data, &file_size, (char*)decrypted_aes_key, &decrypted_size);

  if (!decrypted_data) {
    printf("文件解密失败\n");
    free(encrypted_data);
    free(decrypted_aes_key);
    return;
  }

  // 生成输出路径并写入解密后的文件
  char out_path[256];
  sprintf_s(out_path, sizeof(out_path), "%s.dec", path);
  file_write(out_path, decrypted_data, decrypted_size);
  printf("文件已解密保存至: %s\n", out_path);

  // 释放资源
  free(encrypted_data);
  free(decrypted_data);
  free(decrypted_aes_key);
}

// 初始化一对一聊天
// 初始化一对一聊天会话
void init_one_on_one_chat() {
  // 生成RSA密钥对：使用自定义RSA_key函数生成公钥和私钥
  // rsa_public_key 和 rsa_private_key 是全局变量，用于存储密钥
  RSA_key(&rsa_public_key, &rsa_private_key);

  // 打印生成的RSA公钥，用于分享给对方
  printf("\n您的RSA公钥:\n%s\n", rsa_public_key);
  // 打印生成的RSA私钥，提示用户妥善保存（私钥用于解密消息）
  printf("您的RSA私钥(请妥善保存):\n%s\n", rsa_private_key);

  // 获取对方公钥：用户需要粘贴对方的公钥以建立安全通信
  printf("请粘贴对方的RSA公钥(以空行结束):\n");
  // 初始化缓冲区存储对方公钥
  char pub_key[4096] = { 0 };  // 4096字节缓冲区，足够存储PEM格式的RSA公钥
  char line[256];  // 临时存储每行输入

  // 逐行读取用户输入，直到遇到空行（仅包含换行符）
  while (fgets(line, sizeof(line), stdin)) { // 修复了缺少右括号的问题
    // 检查是否为空行（第一个字符为换行符）
    if (line[0] == '\n') break;
    // 将行内容追加到pub_key缓冲区，使用安全版本strcat_s避免缓冲区溢出
    strcat_s(pub_key, sizeof(pub_key), line);
  }

  // 如果之前已存在对方公钥，释放其内存（避免内存泄漏）
  if (partner_public_key) free(partner_public_key);
  // 使用_strdup创建对方公钥的副本（动态内存分配）
  partner_public_key = _strdup(pub_key);

  // 选择角色：用户决定是发送方还是接收方，影响消息收发顺序
    printf("请选择您的角色:\n");
    printf("1. 发送方(先发送消息)\n");
    printf("2. 接收方(先接收消息)\n");
    int role;
    // 读取用户选择，使用安全版本scanf_s避免缓冲区溢出
  xuanze:
    scanf_s("%d", &role);
    if (role != 1 && role != 2)
    {
      printf("错误，请输入1/2\n");
      goto xuanze;
    
    }
    // 清空输入缓冲区，避免残留字符影响后续输入
    clear_input_buffer();
    // 将角色存储到全局变量chat_role中
    chat_role = role;

    // 提示用户初始化完成
    printf("聊天初始化完成! 输入/exit退出聊天\n");
}

// 初始化群聊会话
void init_group_chat() {
  // 选择角色：用户决定是群主（创建群）还是成员（加入群）
  printf("请选择您的角色:\n");
  printf("1. 群主(创建群聊)\n");
  printf("2. 成员(加入群聊)\n");
  int role;
  scanf_s("%d", &role);
  clear_input_buffer();

  // 处理群主逻辑
  if (role == 1) {
    // 设置全局角色为群主（值3）
    chat_role = 3;

    // 生成RSA密钥对：群主需要自己的密钥对
    RSA_key(&rsa_public_key, &rsa_private_key);
    printf("\n您的RSA公钥:\n%s\n", rsa_public_key);

    // 生成AES群密钥：使用32字节（256位）密钥用于对称加密
    if (group_aes_key) free(group_aes_key);  // 释放旧密钥（如果存在）
    // 分配32字节内存存储AES密钥
    group_aes_key = malloc(32);
    // 使用OpenSSL RAND_bytes生成密码学安全的随机密钥
    RAND_bytes(group_aes_key, 32);
    group_aes_key_size = 32;  // 存储密钥大小

    // 获取成员公钥：群主需要收集所有成员的公钥
    printf("请粘贴成员的RSA公钥(以空行结束):\n");
    char pub_key[4096] = { 0 };
    char line[256];

    while (fgets(line, sizeof(line), stdin)) { // 修复了缺少右括号的问题
      if (line[0] == '\n') break;
      strcat_s(pub_key, sizeof(pub_key), line);
    }

    // 使用RSA加密AES群密钥：用成员的公钥加密对称密钥
    long encrypted_key_size;
    // 调用自定义enc_RSA函数加密AES密钥，返回加密后的数据
    unsigned char* encrypted_aes_key = enc_RSA(group_aes_key, &group_aes_key_size, (unsigned char*)pub_key, &encrypted_key_size);

    // 检查加密是否成功
    if (!encrypted_aes_key) {
      printf("RSA加密失败\n");
      return;
    }

    // 将加密后的二进制数据转换为Base64字符串，便于文本传输
    char* encrypted_key_base64 = base64_encode(encrypted_aes_key, encrypted_key_size);
    if (!encrypted_key_base64) {
      printf("Base64编码失败\n");
      free(encrypted_aes_key);  // 释放加密数据内存
      return;
    }

    // 输出Base64格式的加密密钥，供分发给成员
    printf("加密的AES群密钥(Base64):\n%s\n", encrypted_key_base64);
    printf("请将此密钥分发给群成员\n");

    // 释放临时内存
    free(encrypted_aes_key);
    free(encrypted_key_base64);
  }
  else if (role == 2) {
    // 处理成员逻辑
    chat_role = 4;  // 设置全局角色为成员（值4）

    // 生成成员自己的RSA密钥对
    RSA_key(&rsa_public_key, &rsa_private_key);
    printf("\n您的RSA公钥:\n%s\n", rsa_public_key);

    // 获取群主公钥：用于验证和加密发送给群主的消息
    printf("请粘贴群主的RSA公钥(以空行结束):\n");
    char pub_key[4096] = { 0 };
    char line[256];

    while (fgets(line, sizeof(line), stdin)) { // 修复了缺少右括号的问题
      if (line[0] == '\n') break;
      strcat_s(pub_key, sizeof(pub_key), line);
    }

    // 保存群主公钥到全局变量
    if (partner_public_key) free(partner_public_key);
    partner_public_key = _strdup(pub_key);

    // 获取加密的AES群密钥（Base64格式）
    printf("请粘贴加密的AES群密钥(Base64):\n");
    char encrypted_key_base64[4096] = { 0 };
    fgets(encrypted_key_base64, sizeof(encrypted_key_base64), stdin);
    // 移除末尾换行符（fgets会保留换行符）
    encrypted_key_base64[strcspn(encrypted_key_base64, "\n")] = 0;

    // 解码Base64字符串获取二进制加密数据
    size_t encrypted_key_size;
    unsigned char* encrypted_key = base64_decode(encrypted_key_base64, &encrypted_key_size);
    if (!encrypted_key) {
      printf("Base64解码失败\n");
      return;
    }

    // 使用成员的RSA私钥解密AES群密钥
    long decrypted_key_size;
    unsigned char* decrypted_aes_key = dec_RSA(encrypted_key, (long*)&encrypted_key_size, rsa_private_key, &decrypted_key_size);

    // 释放加密数据内存
    free(encrypted_key);

    // 检查解密结果：应为32字节的AES密钥
    if (!decrypted_aes_key || decrypted_key_size != 32) {
      printf("AES密钥解密失败\n");
      return;
    }

    // 保存解密后的AES群密钥
    if (group_aes_key) free(group_aes_key);
    group_aes_key = malloc(32);
    memcpy(group_aes_key, decrypted_aes_key, 32);
    group_aes_key_size = 32;
    free(decrypted_aes_key);  // 释放临时解密数据

    printf("已成功加入群聊!\n");
  }
  else {
    printf("无效选择\n");
  }
}

// 加密聊天消息：根据聊天类型（一对一或群聊）选择加密方式
char* encrypt_chat_message(const char* message) {
  // 一对一聊天：使用RSA加密
  if (chat_role == 1 || chat_role == 2) {
    // 获取消息长度
    long msg_len = strlen(message);
    long encrypted_size;
    // 使用对方公钥加密消息（自定义enc_RSA函数）
    unsigned char* encrypted = enc_RSA((unsigned char*)message, &msg_len, partner_public_key, &encrypted_size);
    if (!encrypted) return NULL;

    // 将加密后的二进制数据转换为Base64字符串便于传输
    char* base64_msg = base64_encode(encrypted, encrypted_size);
    free(encrypted);  // 释放原始加密数据
    return base64_msg;
  }
  // 群聊：使用AES对称加密
  else if (chat_role == 3 || chat_role == 4) {
    long msg_len = strlen(message);
    long encrypted_size;
    // 使用群AES密钥加密消息（自定义enc_AES函数）
    unsigned char* encrypted = enc_AES((unsigned char*)message, &msg_len, (char*)group_aes_key, &encrypted_size);
    if (!encrypted) return NULL;

    // 转换为Base64
    char* base64_msg = base64_encode(encrypted, encrypted_size);
    free(encrypted);
    return base64_msg;
  }
  return NULL;  // 未知角色返回空
}

// 解密聊天消息：处理接收到的加密消息
char* decrypt_chat_message(const char* encrypted_base64) {
  // 解码Base64字符串获取二进制加密数据
  size_t encrypted_size;
  unsigned char* encrypted = base64_decode(encrypted_base64, &encrypted_size);
  if (!encrypted) return NULL;

  char* decrypted = NULL;  // 初始化解密结果

  // 一对一聊天：使用RSA解密
  if (chat_role == 1 || chat_role == 2) {
    long decrypted_size;
    // 使用自己的私钥解密（自定义dec_RSA函数）
    unsigned char* result = dec_RSA(encrypted, (long*)&encrypted_size, rsa_private_key, &decrypted_size);
    if (result) {
      // 添加字符串终止符并复制结果
      result[decrypted_size] = '\0';
      decrypted = _strdup((char*)result);
      free(result);  // 释放原始解密数据
    }
  }
  // 群聊：使用AES解密
  else if (chat_role == 3 || chat_role == 4) {
    long decrypted_size;
    // 使用群AES密钥解密（自定义dec_AES函数）
    unsigned char* result = dec_AES(encrypted, (long*)&encrypted_size, (char*)group_aes_key, &decrypted_size);
    if (result) {
      result[decrypted_size] = '\0';
      decrypted = _strdup((char*)result);
      free(result);
    }
  }

  free(encrypted);  // 释放Base64解码后的数据
  return decrypted; // 返回解密后的字符串（需调用者释放内存）
}

// 聊天界面主循环
void chat_interface(int is_group) {
  printf("\n加密聊天已启动! 输入/exit退出聊天\n");

  // 如果是接收方（一对一聊天），先等待对方发送第一条消息
  if (!is_group && chat_role == 2) {
    printf("等待对方消息...\n");
    char encrypted_base64[4096];  // 存储接收到的Base64加密消息
    while (1) {
      printf("> ");
      fgets(encrypted_base64, sizeof(encrypted_base64), stdin);
      // 移除换行符
      encrypted_base64[strcspn(encrypted_base64, "\n")] = 0;

      // 检查退出命令
      if (strcmp(encrypted_base64, "/exit") == 0) return;

      // 尝试解密消息
      char* decrypted_msg = decrypt_chat_message(encrypted_base64);
      if (decrypted_msg) {
        printf("对方: %s\n", decrypted_msg);
        free(decrypted_msg);  // 释放解密消息内存
        break;  // 成功解密后跳出等待循环
      }
      else {
        printf("解密失败，请重试\n");
      }
    }
  }

  // 主聊天循环：交替发送和接收消息
  while (1) {
    // 发送消息部分
    char message[1024];  // 存储原始消息
    printf("你: ");
    fgets(message, sizeof(message), stdin);
    message[strcspn(message, "\n")] = 0;  // 移除换行符

    // 检查退出命令
    if (strcmp(message, "/exit") == 0) break;

    // 加密消息
    char* encrypted_msg = encrypt_chat_message(message);
    if (encrypted_msg) {
      // 输出Base64格式的加密消息（实际应用中应发送给对方）
      printf("加密消息(Base64): %s\n", encrypted_msg);
      free(encrypted_msg);  // 释放加密消息内存
    }
    else {
      printf("加密失败\n");
      continue;  // 加密失败时跳过接收部分
    }

    // 接收消息部分
    printf("等待对方消息...\n");
    char encrypted_resp[4096];  // 存储接收到的加密消息
    while (1) {
      printf("> ");
      fgets(encrypted_resp, sizeof(encrypted_resp), stdin);
      encrypted_resp[strcspn(encrypted_resp, "\n")] = 0;

      if (strcmp(encrypted_resp, "/exit") == 0) return;

      // 尝试解密消息
      char* decrypted_resp = decrypt_chat_message(encrypted_resp);
      if (decrypted_resp) {
        printf("对方: %s\n", decrypted_resp);
        free(decrypted_resp);
        break;  // 成功解密后跳出接收循环
      }
      else {
        printf("解密失败，请重试\n");
      }
    }
  }
}

// 主函数
int main() {
  int choice, sub_choice;

  while (1) {
    printf("\n==================================================\n");
    printf("加密工具 v1.4\n");
    printf("==================================================\n");
    printf("1. 文件加密\n");
    printf("2. 文件哈希工具\n");
    printf("3. 加密聊天\n");
    printf("4. 文件解密\n");
    printf("5. 使用教程\n");
    printf("0. 退出\n");
    printf("==================================================\n");
    printf("请选择操作: ");

    scanf_s("%d", &choice);
    clear_input_buffer();

    switch (choice) {
    case 0:
      printf("感谢使用，再见!\n");
      // 清理资源
      if (rsa_public_key) free(rsa_public_key);
      if (rsa_private_key) free(rsa_private_key);
      if (partner_public_key) free(partner_public_key);
      if (group_aes_key) free(group_aes_key);
      return 0;

    case 1: // 文件加密
      printf("\n文件加密模式:\n");
      printf("1. AES加密\n");
      printf("2. RSA+AES加密\n");
      printf("0. 返回主菜单\n");
      printf("请选择加密方式: ");

      scanf_s("%d", &sub_choice);
      clear_input_buffer();

      if (sub_choice == 0) break;
      if (sub_choice == 1) encrypt_file_aes();
      else if (sub_choice == 2) encrypt_file_rsa_aes();
      else printf("无效选择\n");
      break;

    case 2: // 文件哈希工具
      printf("\n文件哈希工具:\n");
      printf("1. 文件哈希计算\n");
      printf("2. 文件哈希比较\n");
      printf("0. 返回主菜单\n");
      printf("请选择操作: ");

      scanf_s("%d", &sub_choice);
      clear_input_buffer();

      if (sub_choice == 0) break;
      if (sub_choice == 1) file_hash_tool();
      else if (sub_choice == 2) file_hash_compare();
      else printf("无效选择\n");
      break;

    case 3: // 加密聊天
      printf("\n加密聊天模式:\n");
      printf("1. 一对一聊天\n");
      printf("2. 群聊\n");
      printf("0. 返回主菜单\n");
      printf("请选择聊天类型: ");

      scanf_s("%d", &sub_choice);
      clear_input_buffer();

      if (sub_choice == 0) break;
      if (sub_choice == 1) {
        init_one_on_one_chat();
        chat_interface(0); // 0表示一对一聊天
      }
      else if (sub_choice == 2) {
        init_group_chat();
        chat_interface(1); // 1表示群聊
      }
      else printf("无效选择\n");
      break;

    case 4: // 文件解密
      printf("\n文件解密模式:\n");
      printf("1. AES解密\n");
      printf("2. RSA+AES解密\n");
      printf("0. 返回主菜单\n");
      printf("请选择解密方式: ");

      scanf_s("%d", &sub_choice);
      clear_input_buffer();

      if (sub_choice == 0) break;
      if (sub_choice == 1) decrypt_file_aes();
      else if (sub_choice == 2) decrypt_file_rsa_aes();
      else printf("无效选择\n");
      break;

    case 5: // 使用教程
      show_tutorial();
      break;

    default:
      printf("无效选择，请重新输入\n");
      break;
    }
  }
}