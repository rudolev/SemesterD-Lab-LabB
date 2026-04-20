// 212196968 - 319127379

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SigNameLength 16

typedef struct virus {
    unsigned short SigSize;
    unsigned char* VirusName;
    unsigned char* Sig;
} virus;

typedef struct link {
    struct link *nextVirus;
    virus *vir;
} link;

typedef struct {
    char letter;
    char *description;
    void (*fun)(char*);
} menu_item;

int big_endian = 0;
link *virus_list = NULL; // first virus in the list because we add to the end 

virus* readVirus(FILE* f) {
    virus* v = malloc(sizeof(virus));
    if (fread(&v->SigSize, 2, 1, f) != 1) {
        free(v);
        return NULL;
    }
    
    if (big_endian) {
        v->SigSize = (v->SigSize << 8) | (v->SigSize >> 8);
    }

    v->VirusName = malloc(SigNameLength);
    fread(v->VirusName, SigNameLength, 1, f);
    v->Sig = malloc(v->SigSize);
    fread(v->Sig, v->SigSize, 1, f);

    return v;
}

void printVirus(virus* virus, FILE* output) {
    if (virus != NULL) {
        fprintf(output, "Virus name: %s\n", virus->VirusName);
        fprintf(output, "Virus size: %d\n", virus->SigSize);
        fprintf(output, "signature:\n");
        for (int i = 0; i < virus->SigSize; i++) {
            fprintf(output, "%02X ", virus->Sig[i]);
        }
        fprintf(output, "\n\n");
    }
}

link* list_append(link* virus_list, virus* data) {
    link* new_link = malloc(sizeof(link));
    new_link->vir = data;
    new_link->nextVirus = NULL;

    if (virus_list == NULL) {
        return new_link;
    }

    link* curLink = virus_list;
    while (curLink->nextVirus != NULL) { // we do this becaue in their example file they printed froms start to finish 
        curLink = curLink->nextVirus;    // so we want to keep this order in the linked list 
    }
    curLink->nextVirus = new_link;
    return virus_list;
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
    if (f == NULL) {
        printf("couldn't open file ");
        return;
    }
    fseek(f, signatureOffset, SEEK_SET);
    unsigned char ret = 0xC3; 
    fwrite(&ret, 1, 1, f);
    fclose(f);
    printf("neutralized virus on offset  %d\n", signatureOffset);
}

int get_big_endian(char* magic) {
    if (strncmp(magic, "VIRL", 4) == 0) 
        return 0;
    else if (strncmp(magic, "VIRB", 4) == 0)    
        return 1;
    return -1;
}

void load_signatures_wrapper(char* inspectFileName) {
    char sigFileName[256];
    printf("Enter signature file name: ");
    fgets(sigFileName, sizeof(sigFileName), stdin);
    sigFileName[strcspn(sigFileName, "\n")] = 0;
    FILE* f = fopen(sigFileName, "rb");
    if (f == NULL) {
        printf("failed opening signatures\n");
        return;
    }
    char magic[4];
    fread(magic, 4, 1, f);
    big_endian = get_big_endian(magic);
    if (big_endian == -1) {
        printf("bad magic number.\n");
        fclose(f);
        return;
    }
    if (virus_list != NULL) {
        list_free(virus_list);
    }
    virus_list = NULL;
    virus* v;
    while ((v = readVirus(f)) != NULL) {
        virus_list = list_append(virus_list, v);
    }
    fclose(f);
}

void print_signatures_wrapper(char* inspectFileName) {
    if (virus_list) list_print(virus_list, stdout);
}

void select_file_wrapper(char* inspectFileName) {
    printf("Enter file to inspect: ");
    fgets(inspectFileName, 256, stdin);
    inspectFileName[strcspn(inspectFileName, "\n")] = 0;
}

void detect_viruses_wrapper(char* inspectFileName) {
    if (inspectFileName[0] == 0) {
        printf("No file selected.\n");
        return;
    }
    FILE* inf = fopen(inspectFileName, "rb");
    if (!inf) {
        printf("failed opening inspection file\n");
        return;
    }
    char buffer[10000];
    int n = fread(buffer, 1, 10000, inf);
    detect_virus(buffer, n, virus_list);
    fclose(inf);
}

void fix_file_wrapper(char* inspectFileName) {
    if (inspectFileName[0] == 0 || !virus_list) return;
    FILE* fixf = fopen(inspectFileName, "rb");
    if (!fixf) return;
    char fixBuf[10000];
    int fixN = fread(fixBuf, 1, 10000, fixf);
    fclose(fixf);
    for (unsigned int i = 0; i < (unsigned int)fixN; i++) {
        link* curr = virus_list;
        while (curr != NULL) {
            if (i + curr->vir->SigSize <= (unsigned int)fixN && memcmp(fixBuf + i, curr->vir->Sig, curr->vir->SigSize) == 0) {
                neutralize_virus(inspectFileName, i);
            }
            curr = curr->nextVirus;
        }
    }
}

void quit_wrapper(char* inspectFileName) {
    if (virus_list) list_free(virus_list);
    exit(0);
}

int main(int argc, char **argv) {
    char choice[10];
    char inspectFileName[256] = "";

    menu_item menu[] = {
        {'L', "Load signatures", load_signatures_wrapper},
        {'P', "Print signatures", print_signatures_wrapper},
        {'S', "Select file to inspect", select_file_wrapper},
        {'D', "Detect viruses", detect_viruses_wrapper},
        {'F', "Fix file", fix_file_wrapper},
        {'Q', "Quit", quit_wrapper},
        {0, NULL, NULL}
    };

    while (1) {
        for (int i = 0; menu[i].description != NULL; i++) {
            printf("<%c>%s\n", menu[i].letter, menu[i].description + 1);
        }
        if (fgets(choice, sizeof(choice), stdin) == NULL) break;
        
        for (int i = 0; menu[i].description != NULL; i++) {
            if (choice[0] == menu[i].letter) {
                menu[i].fun(inspectFileName);
                break;
            }
        }
    }
    return 0;
}