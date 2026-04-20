#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct virus {
    unsigned short SigSize;
    unsigned char* VirusName;
    unsigned char* Sig;
} virus;

typedef struct link {
    struct link *nextVirus;
    virus *vir;
} link;

void printVirus(virus* v, FILE* output) {
    if (v != NULL) {
        fprintf(output, "Virus name: %s\n", v->VirusName);
        fprintf(output, "Virus size: %d\n", v->SigSize);
        fprintf(output, "signature:\n");
        for (int i = 0; i < v->SigSize; i++) {
            fprintf(output, "%02X ", v->Sig[i]);
        }
        fprintf(output, "\n\n");
    }
}

virus* readVirus(FILE* f, int is_big_endian) {
    virus* v = malloc(sizeof(virus));
    if (fread(&v->SigSize, 2, 1, f) != 1) {
        free(v);
        return NULL;
    }

    if (is_big_endian) {
        v->SigSize = (v->SigSize << 8) | (v->SigSize >> 8);
    }

    v->VirusName = malloc(16);
    fread(v->VirusName, 16, 1, f);

    v->Sig = malloc(v->SigSize);
    fread(v->Sig, v->SigSize, 1, f);

    return v;
}

/* --- Linked List Functions --- */

link* list_append(link* virus_list, virus* data) {
    link* new_link = malloc(sizeof(link));
    new_link->vir = data;
    new_link->nextVirus = virus_list;
    return new_link;
}

void list_print(link *virus_list, FILE* output) {
    while (virus_list != NULL) {
        printVirus(virus_list->vir, output);
        virus_list = virus_list->nextVirus;
    }
}

void list_free(link *virus_list) {
    while (virus_list != NULL) {
        link* temp = virus_list;
        virus_list = virus_list->nextVirus;
        free(temp->vir->VirusName);
        free(temp->vir->Sig);
        free(temp->vir);
        free(temp);
    }
}

/* --- Detection and Neutralization --- */

void detect_virus(char *buffer, unsigned int size, link *virus_list) {
    for (unsigned int i = 0; i < size; i++) {
        link* curr = virus_list;
        while (curr != NULL) {
            if (i + curr->vir->SigSize <= size) {
                if (memcmp(buffer + i, curr->vir->Sig, curr->vir->SigSize) == 0) {
                    printf("Offset: %u\nVirus: %s\nSize: %d\n", 
                            i, curr->vir->VirusName, curr->vir->SigSize);
                }
            }
            curr = curr->nextVirus;
        }
    }
}

void neutralize_virus(char *fileName, int signatureOffset) {
    FILE* f = fopen(fileName, "r+b");
    if (!f) {
        perror("Error opening file for fixing");
        return;
    }
    fseek(f, signatureOffset, SEEK_SET);
    unsigned char ret = 0xC3; 
    fwrite(&ret, 1, 1, f);
    fclose(f);
    printf("Neutralized virus at offset %d\n", signatureOffset);
}

int get_endian(char* magic) {
    if (strncmp(magic, "VIRL", 4) == 0) 
        return 0;
    else if (strncmp(magic, "VIRB", 4) == 0)    
        return 1;

    return -1;
}

int main(int argc, char **argv) {
    char choice[10];
    char sigFileName[256];
    char inspectFileName[256] = "";
    link *virus_list = NULL;
    int is_big_endian = 0;

    while (1) {
        printf("<L>oad signatures\n<P>rint signatures\n<S>elect file to inspect\n<D>etect viruses\n<F>ix file\n<Q>uit\n");
        if (!fgets(choice, sizeof(choice), stdin)) break;

        switch (choice[0]) {
            case 'L':
                printf("Enter signature file name: ");
                fgets(sigFileName, sizeof(sigFileName), stdin);
                sigFileName[strcspn(sigFileName, "\n")] = 0;
                FILE* f = fopen(sigFileName, "rb");
                if (!f) {
                    perror("Error opening signatures");
                    break;
                }
                char magic[4];
                fread(magic, 4, 1, f);
                is_big_endian = get_endian(magic);
                if (is_big_endian == -1) {
                    printf("Incorrect magic number.\n");
                    fclose(f);
                    break;
                }
                if (virus_list) list_free(virus_list);
                virus_list = NULL;
                virus* v;
                while ((v = readVirus(f, is_big_endian)) != NULL) {
                    virus_list = list_append(virus_list, v);
                }
                fclose(f);
                break;

            case 'P':
                if (virus_list) list_print(virus_list, stdout);
                break;

            case 'S':
                printf("Enter file to inspect: ");
                fgets(inspectFileName, sizeof(inspectFileName), stdin);
                inspectFileName[strcspn(inspectFileName, "\n")] = 0;
                break;

            case 'D':
                if (inspectFileName[0] == 0) {
                    printf("No file selected.\n");
                    break;
                }
                FILE* inf = fopen(inspectFileName, "rb");
                if (!inf) {
                    perror("Error opening inspection file");
                    break;
                }
                char buffer[10000];
                int n = fread(buffer, 1, 10000, inf);
                detect_virus(buffer, n, virus_list);
                fclose(inf);
                break;

            case 'F':
                if (inspectFileName[0] == 0 || !virus_list) break;
                FILE* fixf = fopen(inspectFileName, "rb");
                char fixBuf[10000];
                int fixN = fread(fixBuf, 1, 10000, fixf);
                fclose(fixf);
                for (unsigned int i = 0; i < fixN; i++) {
                    link* curr = virus_list;
                    while (curr != NULL) {
                        if (i + curr->vir->SigSize <= fixN && memcmp(fixBuf + i, curr->vir->Sig, curr->vir->SigSize) == 0) {
                            neutralize_virus(inspectFileName, i);
                        }
                        curr = curr->nextVirus;
                    }
                }
                break;

            case 'Q':
                if (virus_list) list_free(virus_list);
                return 0;
        }
    }
    return 0;
}