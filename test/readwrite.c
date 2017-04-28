#include <stdlib.h>
#include <stdio.h>

void
writeToFile (char* name, char* contents) {
  FILE* f = fopen(name, "w");
  if (f == NULL) {
    fprintf(stderr, "Failed to open file '%s' for reading; exiting...\n", name);
    exit(1);
  };
  
  fprintf(f, contents);
  
  fclose(f);
}

char *
readFromFile (char* name) {
  FILE* f = fopen(name, "r");
  char *retVal = malloc(sizeof(char) * 1025);
  if (f == NULL) {
    fprintf(stderr, "Cannot open file '%s' for reading; exiting...", name);
    exit(1);
  }

  fgets(retVal, 1024, f);
  fclose(f);
  return retVal;
}

int
main(int argc, char **argv) {
  char* name = argv[0];
  if (argc != 3) {
    fprintf(stderr, "Usage: %s <read file> <write file>\n", name);
    exit(1);
  }
  char* contents = readFromFile(argv[1]);
  writeToFile(argv[2], contents);
  free(contents);
}
