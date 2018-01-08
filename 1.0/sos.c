#include <stdio.h>
#include <math.h>
#include <string.h>
#include <stdlib.h>

#define MAXLINE 255          /* max number of chars pe line*/
#define HEAD 0               /*  numeric		*/
#define BODYTAG 2            /*  values      */
#define SUBTAG  4            /*  of position */
#define BODY 4               /*  in file     */
#define SUB 6                /*              */

unsigned int hl, dl, sl;    /* length of file */
int key_length;             /* length of key *8 */
int cswitch;					 /* check for -c */
int wswitch;					 /* check for -w */
short x,y,z;                /* loop-counter */
short *bkey;					 /* binary key */
short data_mod;				 /* strlen(data) %4 */
short data_add;				 /* 1 if data_mod != 0 */
short binary[32];				 /* four binary chars of data */
float percent;              /* 100 Percent value for counter */
void toBin(unsigned short dec, short param, short *dest); /*calculate binaries*/
void crypt(short crypt_length); /* the encryption */
void output(unsigned char c);	  /* mask special characters */
void readfile(char *f);		     /* file input */
void tagprint(char *s);			  /* print a html-tag in Javascript-Code */
int strindex(char source[], char *searchfor[], int searchstate); /* Compare */
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
     printf("\t\t Simple Online Security\n\n"
     "Usage:\nSOS [input-file] [output-file] [password] [-c] [-w]\n"
     "\t[input-file]  file you want to encrypt\n"
     "\t[output-file] name of the encrypted file\n"
	  "\t[password]    key for encryption\n"
	  "\t[-c]          exclude percentage counter\n"
     "\t[-w]          encrypt a page bigger than 2.6k in Windows9x\n");
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
        else if(argv[x][1] == 'w')
           wswitch = 1;
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
  fprintf(stream, "  var key;\n  var data;\n"
  "  var x,y,z;\n  var temp;\n  var binary = new Array();\n  var bkey = new Array();\n"
  "  var key_length;\n  var data_mod;\n  var data_add = 0;\n  var data_div;\n  var dec;\n"
  "\n  data = \"");

  key_length = strlen(key)*8;
  if((bkey = (short *)malloc(key_length)) == NULL)      {
     fprintf(stderr, "Error: Not enough memory to allocate buffer!\n");
     exit(1);
  }

  for(z=0;z<key_length/8;z++)
     toBin(key[z], z, bkey);

  if((data_mod = strlen(data) %4) !=0)
     data_add = 1;

  for(y=0;y<strlen(data)/4+data_add;y++)  {		/*Encrypt Data*/
     if(y == ((strlen(data)/4+data_add)-1)&&(data_mod != 0))
  	     crypt(data_mod);
  	  else
        crypt(4);
  }
  fprintf(stream, "\";\n\n  key = prompt (\"Please input your Key\",\"Passwort\");\n"
  "  key_length = key.length*8;\n\n  for(z=0;z<key.length;z++)   {\n"
  "     dec = key.charCodeAt(z);\n     for (x = 0; x < 8; x++)   	{\n"
  "  bkey[((-x)+7)+z*8] =  dec % 2;\n           dec = (dec - (dec % 2))/2;\n"
  "     }\n  }\n\n  if(data_mod = data.length %4 !=0)\n     data_add = 1;\n\n"
  "  data_div = data.length-(data.length%4);\n\n  for(y=0;y<data_div/4+data_add;y++)\n"
  "     if((y == (((data_div/4)+data_add)-1))&&(data_mod != 0))\n"
  "        crypt(data,key,bkey,key_length,y,binary,data_mod);\n     else\n"
  "        crypt(data,key,bkey,key_length,y,binary,4);\n\n"
  "function crypt (data,key,bkey,key_length,y,binary,crypt_length)\n  {\n"
  "  var cipherdata = new Array();\n  var z,x;\n\n  for(z=0;z<crypt_length;z++)\n"
  "     toBin(data.charCodeAt(z+y*4),z,binary);\n\n  for(x=0;x<key.length;x++)   {\n"
  "     for(z = 0; z <crypt_length*8; z++)\n"
  "          if(binary[z] == bkey[((z + 8*x)+y)% key_length])\n           binary[z] = 0;\n"
  "        else\n	   binary[z] = 1;\n  }\n\n  for(x=0;x<crypt_length;x++)   {\n"
  "     temp=0;\n     for(z = 7; z >= 0; z--)\n"
  "     temp = temp + (binary[z +x*8] * Math.pow(2,(-z + 7)));\n"
  "     cipherdata = cipherdata + String.fromCharCode(temp);\n"
  "     document.write(String.fromCharCode(temp));\n  }\n\n  function toBin(dec,z,binary)\n"
  "  {\n    for (x = 0; x < 8; x++)         {\n      binary[((-x)+7)+z*8] =  dec % 2;\n"
  "      dec = (dec -(dec % 2))/2;\n    }\n  }\n}\n");
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

  if(wswitch != 1)	/* -w switch not set*/
     free(data);
  free(key);
  free(head);
  free(sub);
  fclose(stream);
  return 0;
}

void crypt (short crypt_length)
{
  int temp;
  for(z=0;z<crypt_length;z++)
     toBin(data[z+y*4], z, binary);

  for(x=0;x<key_length/8;x++)
     for(z = 0; z <crypt_length*8; z++)
        if(binary[z] == bkey[((z + 8*x)+y)% key_length])
		     binary[z] = 0;
        else
		     binary[z] = 1;

  for(x=0;x<crypt_length;x++)   {
     temp=0;
     for(z = 7; z >= 0; z--)
	  	  temp = temp + (binary[z +x*8] * pow(2,(-z + 7)));
     	  output(temp);
     }
}

void toBin(unsigned short dec, short param, short *dest)
{
  for (x = 0; x < 8; x++)   {
     dest[((-x)+7)+param*8] =  dec % 2;
     dec = dec/2;
  }
}

void output(unsigned char c)
{
  static charcounter;
  static count;

  percent = dl;
  switch(c)   {
     case('\a'):				/*These chars must be masked*/
	     fprintf(stream, "\\007");
		  charcounter += 4;
		  break;
     case('\\'):
	     fprintf(stream, "\\134");
		  charcounter += 4;
		  break;
     case('\?'):
	     fprintf(stream, "\\077");
		  charcounter += 4;
		  break;
     case('\''):
		  fprintf(stream, "\\047");
		  charcounter += 4;
		  break;
     case('\"'):
	     fprintf(stream, "\\042");
		  charcounter += 4;
		  break;
	  case(26):
	     fprintf(stream, "\\032");
		  charcounter += 4;
		  break;
     case(0):
		  fprintf(stream, " ");
        charcounter++;
		  break;
     default:
        if((128 <= c) && (c <= 159))      { /*These chars produce false values*/
           fprintf(stream, "\\%o", c);
	        charcounter += 4;
        }
      else if((9 <= c) && (c <= 15))   {    /* \b, \t, \n, \v, \f, \r*/
	      fprintf(stream, "\\0%o", c);
	      charcounter += 4;
      }
      else      {
         fputc(c, stream);
	      charcounter++;
      }
		break;
  }
  if(charcounter >= 50)   {
     fprintf(stream, "\"+\n         \"");
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
  fprintf(stream, "  window.document.write(\"");
  for(x=0; x<strlen(s); x++)
     if((s[x] == '\n') && (x != strlen(s)-1))
	     fprintf(stream, "\\n\"+\n  \"");
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
