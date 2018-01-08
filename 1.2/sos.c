#include <stdio.h>
#include <math.h>
#include <string.h>
#include <stdlib.h>

#define MAXLINE 256          /* max number of chars pe line*/
#define HEAD 0               /*  numeric		*/
#define BODYTAG 2            /*  values      */
#define SUBTAG  4            /*  of position */
#define BODY 4               /*  in file     */
#define SUB 6                /*              */

void output(unsigned char c);	  /* mask special characters */
void readfile(char *f);		     /* file input */
void tagprint(char *s);			  /* print a html-tag in Javascript-Code */
int strindex(char source[], char *searchfor[], int searchstate); /* Compare */
void rc4_crypt( void );		 /* RC4 Encryption of data */

unsigned int hl, dl, sl;    /* length of file */
int cswitch;					 /* check for -c */
short x,y,z;                /* loop-counter */
float percent;              /* 100 Percent value for counter */
char headendtag[MAXLINE];	 /* </head> */
char bodytag[MAXLINE];		 /* <body>  */
char bodyendtag[MAXLINE];   /* </body> */
char *data;						 /* everything between <body> and </body> */
char *head;						 /* everything above <body> */
char *sub;						 /* everything below </body> */
char *key;					    /* password */
FILE *stream;					 /* File pointer */

int main(int argc, char *argv[])
{
  if(argc == 1) {
     printf("\n\t\t Simple Online Security\n\n"
     "Usage:\nSOS [input-file] [output-file] [password] [-c]\n"
     "\t[input-file]  file you want to encrypt\n"
     "\t[output-file] name of the encrypted file\n"
	  "\t[password]    key for encryption\n"
	  "\t[-c]          exclude percentage counter\n");
	  return 0;
  }
  if(argc < 4) {
     fprintf(stderr, "Error: Too few arguments!\n");
     exit(1);
  }

  if(argc > 4)
     for(x=4;x<argc;x++)
        if(argv[x][1] == 'c')
           cswitch = 1;
        else     {
		     fprintf(stderr,
           "Error: Invalid argument: \"%s\"!\n", argv[x]);
      	  exit(1);
        }

  if((key = (char *)malloc(strlen(argv[3]))) == NULL)   {
     fprintf(stderr, "Not enough memory to allocate buffer!");
	  exit(1);
  }
  strcpy(key, argv[3]);
  readfile(argv[1]);

  if((stream = fopen(argv[2], "w")) == NULL)    {
     fprintf(stderr, "Unable to open output-file \"%s\"", argv[2]);
     exit(1);
  }
  fprintf(stream, "%s"		/*Output Javascript Code*/
  "<script language=\"Javascript\">\n\nfunction main()\n{\n", head);
  tagprint(head);
  tagprint(headendtag);
  tagprint(bodytag);
  fprintf(stream,
  "var seed = new Array(256);\nvar state = new Array(256);\nvar i, n, "
  "temp, xorIndex;\nvar key_x = 0;\nvar key_y = 0;\nvar index1 = 0;\nv"
  "ar index2 = 0;\nvar data = prompt(\"Please enter password:\", \"\")"
  ";\n\n\nvar cipher = \n\t\"");
  rc4_crypt();
  fprintf(stream,
  "\";\n\nn = data.length;\nfor(i = 0; i < 256; i++)	{\n 	state[i] ="
  " i;\n	seed[i] = data.charCodeAt(i%%n);\n}\nfor(i = 0; i < 256; i++)"
  "    {\n	index2 = (seed[index1] + state[i] + index2) %% 256;	temp"
  " = state[i];   state[i] = state[index2];   state[index2] = temp;\n "
  "	index1 = (index1 + 1) %% n;\n}\nfor(i = 0; i <cipher.length; i++"
  ")  { \n	key_x = (key_x + 1) %% 256;\n	key_y = (state[key_x] + key_"
  "y) %% 256;\n	temp = state[key_x];   state[key_x] = state[key_y]; "
  "  state[key_y] = temp;\n	xorIndex = (state[key_x] + state[key_y])"
  " %% 256;\n\n	window.document.write(String.fromCharCode(cipher.cha"
  "rCodeAt(i) ^ state[xorIndex]));\n}\n\n");
  tagprint(bodyendtag);
  tagprint(sub);

  for(x=0;bodytag[x] != '>' && x < strlen(bodytag);x++) /*get position of '>' in bodytag*/
     ;
  if(x == strlen(bodytag))      {
     fprintf(stderr,
     "Error: %s doesn`t have a terminating \'>\'.\n"
     "Check if %s is continued in the next lines.\n"
     "If so put it all on one\n", bodytag, bodytag);
     exit(1);
  }

  bodytag[x] = '\0';
  strcat(bodytag, " onload=\"main();\">\n");				/*put eventhandler in bodytag*/

  fprintf(stream, "}\n</script>\n%s%s%s%s", headendtag, bodytag, bodyendtag, sub);

  free(data);
  free(key);
  free(head);
  free(sub);
  fclose(stream);
  return 0;
}

void output(unsigned char c)
{
  static charcounter;
  static count;

  percent = dl;
  			/*These chars produce false values*/
   if((9 <= c) && (c <= 15) || (128 <= c) && (c <= 159) || c == '\a'
   	|| c == '\\' || c == '\'' || c == '\"' || c == 26 || c == 0)      {
      	fprintf(stream, "\\%s%o", c < 8 ? "00" : c < 80 ? "0" : "" , c);
	 		charcounter += 4;
   } else {
   	fputc(c, stream);
	   charcounter++;
   }

  if(charcounter >= 50)   {
     fprintf(stream, "\"+\n\t\"");
	  charcounter = 0;
  }
  if(cswitch != 1)   {   /* -c switch not set*/
     count++;
     if(count == 1)
	     printf("\n");
     else
	     for(z=0;z<32;z++)       /*Delete last Output*/
		     fputc('\b', stdout);
	     printf("Encryption is %.2f%% done!",(count/percent)*100); /*Print % done*/
	     if((count/percent)*100 == 100)
	        fputc('\n', stdout);
  }
}

void readfile(char *f)
{
  char *pattern[] = {"</head", "</HEAD", "<body", "<BODY" , "</body", "</BODY"};
  char line[MAXLINE];
  int state;
  FILE *stream;

  if((stream = fopen(f, "r")) == NULL) {
     fprintf(stderr, "Error: Unbable to open input file \"%s\"!\n", f);
     exit(1);
  }

  state = HEAD;

  while(fgets(line, MAXLINE, stream) != NULL)	/*This while loop checks the size of*/
     if(strindex(line, pattern, state) >= 0)   /*the file*/
	     state += 2;
     else
  switch(state)   {
     case HEAD:
        if(line[0] == '\n')    /* A newline alone can produce an error*/
		  strcpy(line, " \n");
		  hl += strlen(line);
	     break;
	  case BODY:
        if(line[0] == '\n')
		  strcpy(line, " \n");
	     dl += strlen(line);
	     break;
	  case SUB:
        if(line[0] == '\n')
		  strcpy(line, " \n");
	     sl += strlen(line);
	     break;
  }

  if(state < SUB)      {
     fprintf(stderr,
     "Error: Can`t find %s> tag (or similiar one)!\n"
     "Check if file is a html file.\n"
     "Or check if tag stands alone in one line.\n", pattern[state]);
     exit(1);
  }
  else if(state > SUB) {
     fprintf(stderr,
     "Error: Too many tags!\n"
     "Check if </head> <body> </body> appear only once.\n", pattern[state]);
     exit(1);
  }

  fclose(stream);
  stream = fopen(f, "r");
  state = HEAD;
  if(((head = (char *) malloc(hl)) == NULL)
   ||((data = (char *) malloc(dl)) == NULL)
   ||((sub = (char *) malloc(sl)) == NULL))     {
     fprintf(stderr, "Error: Not enough memory to allocate buffer!\n");
     exit(1);
  }

  strcpy(head, "");
  strcpy(data, "");
  strcpy(sub, "");

  while(fgets(line, MAXLINE, stream) != NULL)		 /*read file*/
     if(strindex(line, pattern, state) >= 0) {
        switch(state)  {
	        case HEAD:
    	        strcpy(headendtag, line);
         	  break;
           case BODYTAG:
              strcpy(bodytag, line);
	           break;
        	  case SUBTAG:
	           strcpy(bodyendtag, line);
        	     break;
	     }
	  state += 2;
     }
     else
	     switch(state)   {
	        case HEAD:
              if(line[0] == '\n')    /* A newline alone can produce an error*/
		           strcpy(line, " \n");
              strcat(head, line);
 	           break;
	        case BODY:
              if(line[0] == '\n')
                 strcpy(line, " \n");
              strcat(data, line);
	           break;
	        case SUB:
              if(line[0] == '\n')
                 strcpy(line, " \n");
	           strcat(sub, line);
	           break;
	     }
  	if(sub[strlen(sub)-1])
   	strcat(sub, "\n");
  fclose(stream);
}

int strindex(char s[], char *t[], int x)
{
  int i, j, k;
  if(x > 4)		/*This can`t normally happen*/
  x = 4;
  for(i = 0; s[i] != '\0'; i++)  {
     for(j=i, k=0; t[x][k]!='\0' && ((s[j]==t[x][k]) || (s[j]==t[x+1][k])); j++, k++)
	     ;
     if (k > 0 && t[x][k] == '\0')
        return i;
  }
  return -1;
}

void tagprint(char *s)
{
  fprintf(stream, "window.document.write(\"");
  for(x=0; x<strlen(s); x++)
     if((s[x] == '\n') && (x != strlen(s)-1))
	     fprintf(stream, "\\n\"+\n\"");
     else if((s[x] == '\n') && (x == strlen(s)-1))
	     fprintf(stream, "\\n\");\n");
     else
	     if(s[x] == '\"')
		     fprintf(stream, "\\042");
        else if(s[x] == '<')
           fprintf(stream, "\\074");
        else
	 	     fputc(s[x], stream);
}

typedef struct rc4_key
{
   unsigned char state[256];
   unsigned char x;
   unsigned char y;
} rc4_key;

#define swap_byte(x,y) t = *(x); *(x) = *(y); *(y) = t

void prepare_key(unsigned char *key_data_ptr, int key_data_len, rc4_key *key);
void rc4(unsigned char *buffer_ptr, int buffer_len, rc4_key *key);

void  rc4_crypt( void )
{
  unsigned char seed[256];
  char digit[5];
  int hex, i;
  int n;
  rc4_key key_rc4;

  n = strlen(key);
  for(i=0; i<256;i++)
		seed[i] = key[i%n];

  prepare_key(seed,n,&key_rc4);
  rc4(data, strlen(data), &key_rc4);
}

void prepare_key(unsigned char *key_data_ptr, int key_data_len, rc4_key *key)
{
  unsigned char t;
  unsigned char index1;
  unsigned char index2;
  unsigned char* state;
  short counter;
  state = &key->state[0];
  for(counter = 0; counter < 256; counter++)
  state[counter] = counter;
  key->x = 0;
  key->y = 0;
  index1 = 0;
  index2 = 0;
  for(counter = 0; counter < 256; counter++)
  {
    index2 = (key_data_ptr[index1] + state[counter] + index2) % 256;
    swap_byte(&state[counter], &state[index2]);
    index1 = (index1 + 1) % key_data_len;
  }
}

void rc4(unsigned char *buffer_ptr, int buffer_len, rc4_key *key)
{
  unsigned char t;
  unsigned char x;
  unsigned char y;
  unsigned char* state;
  unsigned char xorIndex;
  short counter;

  x = key->x;
  y = key->y;
  state = &key->state[0];
  for(counter = 0; counter < buffer_len; counter++)
  {
    x = (x + 1) % 256;
    y = (state[x] + y) % 256;
    swap_byte(&state[x], &state[y]);
    xorIndex = (state[x] + state[y]) % 256;
    output(buffer_ptr[counter] ^= state[xorIndex]);
  }
  key->x = x;
  key->y = y;
}
