__attribute__((noinline)) void* SWORD_OF_THE_HERO(int a, int b, int c) {
  return (void*)(long)(a + b + c);
}

int main(void) {
  SWORD_OF_THE_HERO(1, 2, 3);
  return 0;
}
