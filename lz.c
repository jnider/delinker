/*
 *	unlzexe  --  uncompresses DOS executables (compressed with LZEXE)
 *		     under OpenBSD (and possibly other Unices as well)
 *
 *	32-bit refreshed version by Anders Gavare <g@dd.chalmers.se>
 *
 *	This is practically a port from UNLZEXE for DOS. The original
 *	notes follow below my notes. It will compile under gcc (2.8.1)
 *	but is not compatible with 16-bit systems anymore.
 *
 *	Why would anyone want to unpack DOS executables under Unix? you
 *	might ask. Well, one answer could be to make it easier to read
 *	texts in DOS executables... if you need to do that for some reason.
 *
 *	0.9G	16 Mar 1999	Converting to OpenBSD (refreshing pretty
 *				much all of the code). The output is
 *				a little bit corrupt, though, because
 *				we have 32-bit pointers now, not 16-bit...
 *				Keeping v0.8 and v0.7 comments...
 *	0.9G2	17 Mar 1999	Refreshing more. Fixed bug. I've not tried
 *				to actually execute the resulting DOS
 *				binary, though  :)
 */


/* unlzexe ver 0.5 (PC-VAN UTJ44266 Kou )
*   UNLZEXE converts the compressed file by lzexe(ver.0.90,0.91) to the
*   UNcompressed executable one.
*
*   usage:  UNLZEXE packedfile[.EXE] [unpackedfile.EXE]

v0.6  David Kirschbaum, Toad Hall, kirsch@usasoc.soc.mil, Jul 91
	Problem reported by T.Salmi (ts@uwasa.fi) with UNLZEXE when run
	with TLB-V119 on 386's.
	Stripping out the iskanji and isjapan() stuff (which uses a somewhat
	unusual DOS interrupt) to see if that's what's biting us.

--  Found it, thanks to Dan Lewis (DLEWIS@SCUACC.SCU.EDU).
	Silly us:  didn't notice the "r.h.al=0x3800;" in isjapan().
	Oh, you don't see it either?  INT functions are called with AH
	having the service.  Changing to "r.x.ax=0x3800;".

v0.7  Alan Modra, amodra@sirius.ucs.adelaide.edu.au, Nov 91
    Fixed problem with large files by casting ihead components to long
    in various expressions.
    Fixed MinBSS & MaxBSS calculation (ohead[5], ohead[6]).  Now UNLZEXE
    followed by LZEXE should give the original file.

v0.8  Vesselin Bontchev, bontchev@fbihh.informatik.uni-hamburg.de, Aug 92
    Fixed recognition of EXE files - both 'MZ' and 'ZM' in the header
    are recognized.
    Recognition of compressed files made more robust - now just
    patching the 'LZ90' and 'LZ91' strings will not fool the program.
*/


#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define	VERSION "0.9G2"

#define	FAILURE 1
#define	SUCCESS 0

typedef unsigned short WORD;
typedef unsigned char BYTE;
typedef struct
{
	FILE	*fp;
	WORD	buf;
	BYTE	count;
} bitstream;


int reloc90 (FILE *f, FILE *ofile, long fpos);
int reloc91 (FILE *f, FILE *ofile, long fpos);
void initbits (bitstream *,FILE *);
int getbit (bitstream *);

static WORD ihead[0x10], ohead[0x10], inf[8];
static long loadsize;
char tmpfname[256] = "$tmpfil$.exe";
char backup_ext[16] = ".olz";
char ipath[FILENAME_MAX],
     opath[FILENAME_MAX],
     ofname[FILENAME_MAX];

static BYTE sig90 [] = {			/* v0.8 */
    0x06, 0x0E, 0x1F, 0x8B, 0x0E, 0x0C, 0x00, 0x8B,
    0xF1, 0x4E, 0x89, 0xF7, 0x8C, 0xDB, 0x03, 0x1E,
    0x0A, 0x00, 0x8E, 0xC3, 0xB4, 0x00, 0x31, 0xED,
    0xFD, 0xAC, 0x01, 0xC5, 0xAA, 0xE2, 0xFA, 0x8B,
    0x16, 0x0E, 0x00, 0x8A, 0xC2, 0x29, 0xC5, 0x8A,
    0xC6, 0x29, 0xC5, 0x39, 0xD5, 0x74, 0x0C, 0xBA,
    0x91, 0x01, 0xB4, 0x09, 0xCD, 0x21, 0xB8, 0xFF,
    0x4C, 0xCD, 0x21, 0x53, 0xB8, 0x53, 0x00, 0x50,
    0xCB, 0x2E, 0x8B, 0x2E, 0x08, 0x00, 0x8C, 0xDA,
    0x89, 0xE8, 0x3D, 0x00, 0x10, 0x76, 0x03, 0xB8,
    0x00, 0x10, 0x29, 0xC5, 0x29, 0xC2, 0x29, 0xC3,
    0x8E, 0xDA, 0x8E, 0xC3, 0xB1, 0x03, 0xD3, 0xE0,
    0x89, 0xC1, 0xD1, 0xE0, 0x48, 0x48, 0x8B, 0xF0,
    0x8B, 0xF8, 0xF3, 0xA5, 0x09, 0xED, 0x75, 0xD8,
    0xFC, 0x8E, 0xC2, 0x8E, 0xDB, 0x31, 0xF6, 0x31,
    0xFF, 0xBA, 0x10, 0x00, 0xAD, 0x89, 0xC5, 0xD1,
    0xED, 0x4A, 0x75, 0x05, 0xAD, 0x89, 0xC5, 0xB2,
    0x10, 0x73, 0x03, 0xA4, 0xEB, 0xF1, 0x31, 0xC9,
    0xD1, 0xED, 0x4A, 0x75, 0x05, 0xAD, 0x89, 0xC5,
    0xB2, 0x10, 0x72, 0x22, 0xD1, 0xED, 0x4A, 0x75,
    0x05, 0xAD, 0x89, 0xC5, 0xB2, 0x10, 0xD1, 0xD1,
    0xD1, 0xED, 0x4A, 0x75, 0x05, 0xAD, 0x89, 0xC5,
    0xB2, 0x10, 0xD1, 0xD1, 0x41, 0x41, 0xAC, 0xB7,
    0xFF, 0x8A, 0xD8, 0xE9, 0x13, 0x00, 0xAD, 0x8B,
    0xD8, 0xB1, 0x03, 0xD2, 0xEF, 0x80, 0xCF, 0xE0,
    0x80, 0xE4, 0x07, 0x74, 0x0C, 0x88, 0xE1, 0x41,
    0x41, 0x26, 0x8A, 0x01, 0xAA, 0xE2, 0xFA, 0xEB,
    0xA6, 0xAC, 0x08, 0xC0, 0x74, 0x40, 0x3C, 0x01,
    0x74, 0x05, 0x88, 0xC1, 0x41, 0xEB, 0xEA, 0x89
}, sig91 [] = {
    0x06, 0x0E, 0x1F, 0x8B, 0x0E, 0x0C, 0x00, 0x8B,
    0xF1, 0x4E, 0x89, 0xF7, 0x8C, 0xDB, 0x03, 0x1E,
    0x0A, 0x00, 0x8E, 0xC3, 0xFD, 0xF3, 0xA4, 0x53,
    0xB8, 0x2B, 0x00, 0x50, 0xCB, 0x2E, 0x8B, 0x2E,
    0x08, 0x00, 0x8C, 0xDA, 0x89, 0xE8, 0x3D, 0x00,
    0x10, 0x76, 0x03, 0xB8, 0x00, 0x10, 0x29, 0xC5,
    0x29, 0xC2, 0x29, 0xC3, 0x8E, 0xDA, 0x8E, 0xC3,
    0xB1, 0x03, 0xD3, 0xE0, 0x89, 0xC1, 0xD1, 0xE0,
    0x48, 0x48, 0x8B, 0xF0, 0x8B, 0xF8, 0xF3, 0xA5,
    0x09, 0xED, 0x75, 0xD8, 0xFC, 0x8E, 0xC2, 0x8E,
    0xDB, 0x31, 0xF6, 0x31, 0xFF, 0xBA, 0x10, 0x00,
    0xAD, 0x89, 0xC5, 0xD1, 0xED, 0x4A, 0x75, 0x05,
    0xAD, 0x89, 0xC5, 0xB2, 0x10, 0x73, 0x03, 0xA4,
    0xEB, 0xF1, 0x31, 0xC9, 0xD1, 0xED, 0x4A, 0x75,
    0x05, 0xAD, 0x89, 0xC5, 0xB2, 0x10, 0x72, 0x22,
    0xD1, 0xED, 0x4A, 0x75, 0x05, 0xAD, 0x89, 0xC5,
    0xB2, 0x10, 0xD1, 0xD1, 0xD1, 0xED, 0x4A, 0x75,
    0x05, 0xAD, 0x89, 0xC5, 0xB2, 0x10, 0xD1, 0xD1,
    0x41, 0x41, 0xAC, 0xB7, 0xFF, 0x8A, 0xD8, 0xE9,
    0x13, 0x00, 0xAD, 0x8B, 0xD8, 0xB1, 0x03, 0xD2,
    0xEF, 0x80, 0xCF, 0xE0, 0x80, 0xE4, 0x07, 0x74,
    0x0C, 0x88, 0xE1, 0x41, 0x41, 0x26, 0x8A, 0x01,
    0xAA, 0xE2, 0xFA, 0xEB, 0xA6, 0xAC, 0x08, 0xC0,
    0x74, 0x34, 0x3C, 0x01, 0x74, 0x05, 0x88, 0xC1,
    0x41, 0xEB, 0xEA, 0x89, 0xFB, 0x83, 0xE7, 0x0F,
    0x81, 0xC7, 0x00, 0x20, 0xB1, 0x04, 0xD3, 0xEB,
    0x8C, 0xC0, 0x01, 0xD8, 0x2D, 0x00, 0x02, 0x8E,
    0xC0, 0x89, 0xF3, 0x83, 0xE6, 0x0F, 0xD3, 0xEB,
    0x8C, 0xD8, 0x01, 0xD8, 0x8E, 0xD8, 0xE9, 0x72
}, sigbuf [sizeof sig90];


/* EXE header test (is it LZEXE file?) */
int rdhead (FILE *ifile ,int *ver)
  {
    long entry; 	/* v0.8 */

    /*  v0.8  */
    if (fread (ihead, 1, sizeof ihead, ifile) != sizeof ihead)
	return FAILURE;
    memcpy (ohead, ihead, sizeof ohead);
    if((ihead [0] != 0x5a4d && ihead [0] != 0x4d5a) ||
       ihead [0x0d] != 0 || ihead [0x0c] != 0x1c)
	return FAILURE;
    entry = ((long) (ihead [4] + ihead[0x0b]) << 4) + ihead[0x0a];
    if (fseek (ifile, entry, SEEK_SET) != 0)
	return FAILURE;
    if (fread (sigbuf, 1, sizeof sigbuf, ifile) != sizeof sigbuf)
	return FAILURE;
    if (memcmp (sigbuf, sig90, sizeof sigbuf) == 0)
      {
	*ver = 90;
	return SUCCESS;
      }
    if (memcmp (sigbuf, sig91, sizeof sigbuf) == 0)
      {
	*ver = 91;
	return SUCCESS;
      }
    return FAILURE;
  }


/* make relocation table */
int mkreltbl (FILE *ifile, FILE *ofile, int ver)
  {
    long fpos;
    int i;

    fpos = (long)(ihead[0x0b]+ihead[4])<<4;		/* goto CS:0000 */
    fseek (ifile, fpos, SEEK_SET);
    if (fread (inf, sizeof inf[0], 0x08, ifile) < 0)
		return -1;

    ohead[0x0a]=inf[0]; 	/* IP */
    ohead[0x0b]=inf[1]; 	/* CS */
    ohead[0x08]=inf[2]; 	/* SP */
    ohead[0x07]=inf[3]; 	/* SS */

    /* inf[4]:size of compressed load module (PARAGRAPH)*/
    /* inf[5]:increase of load module size (PARAGRAPH)*/
    /* inf[6]:size of decompressor with  compressed relocation table (BYTE) */
    /* inf[7]:check sum of decompresser with compressd relocation table(Ver.0.90) */

    ohead[0x0c]=0x1c;		/* start position of relocation table */
    fseek (ofile, 0x1cL, SEEK_SET);

    switch (ver)
      {
	case 90:	i=reloc90 (ifile,ofile,fpos);
			break;
	case 91:	i=reloc91 (ifile,ofile,fpos);
			break;
	default:	printf ("bad version 0.%d\n", ver);
			i=FAILURE; break;
      }

    if (i!=SUCCESS)
      {
	printf ("Error at relocation table\n");
	return (FAILURE);
      }

    fpos = ftell (ofile);

    i= (0x200 - (int) fpos) & 0x1ff;
    ohead[4]= (int) ((fpos+i)>>4);

    for( ; i>0; i--)
	putc(0, ofile);
    return(SUCCESS);
  }


/* for LZEXE ver 0.90 */
int reloc90 (FILE *ifile, FILE *ofile, long fpos)
  {
    unsigned int c;
    WORD rel_count=0;
    WORD rel_seg,rel_off;

    /* 0x19d=compressed relocation table address */
    fseek(ifile,fpos+0x19d,SEEK_SET);
    rel_seg = 0;

    do
      {
	if (feof(ifile) || ferror(ifile) || ferror(ofile))
	  return(FAILURE);

	c = getc(ifile) + getc(ifile)*256;

	for(;c>0;c--)
	  {
	    rel_off = getc(ifile) + getc(ifile)*256;

	    putc (rel_off & 255, ofile);
	    putc (rel_off / 256, ofile);
	    putc (rel_seg & 255, ofile);
	    putc (rel_seg / 256, ofile);

	    rel_count++;
	  }

	rel_seg += 0x1000;

      } while (rel_seg!=(0xf000+0x1000));

    ohead[3]=rel_count;
    return(SUCCESS);
  }


/* for LZEXE ver 0.91*/
int reloc91 (FILE *ifile, FILE *ofile, long fpos)
  {
    int span;
    int rel_count=0;
    int rel_seg,rel_off;

    /* 0x158=compressed relocation table address */
    fseek (ifile, fpos+0x158, SEEK_SET);

    rel_off=0; rel_seg=0;

    for(;;)
      {
	if (feof(ifile) || ferror(ifile) || ferror(ofile))
		return(FAILURE);

	if ((span=getc(ifile))==0)
	  {
	    span = getc(ifile) + getc(ifile)*256;
	    if(span==0)
	      {
		rel_seg += 0x0fff;
		continue;
	      }
	    else
	    if(span==1)
		break;
	  }

	rel_off += span;
	rel_seg += (rel_off & ~0x0f)>>4;
	rel_off &= 0x0f;

	putc (rel_off & 255, ofile);
	putc (rel_off / 256, ofile);
	putc (rel_seg & 255, ofile);
	putc (rel_seg / 256, ofile);

	rel_count++;
      }

    ohead[3] = rel_count;
    return (SUCCESS);
  }


/*---------------------*/

/* decompressor routine */
int unpack (FILE *ifile, FILE *ofile)
  {
    int len;
    int span;
    long fpos;
    bitstream bits;
    static BYTE data[0x4500], *p=data;

    fpos = ((long)ihead[0x0b]-(long)inf[4]+(long)ihead[4])<<4;
    fseek (ifile, fpos, SEEK_SET);
    fpos = (long)ohead[4]<<4;
    fseek (ofile, fpos, SEEK_SET);
    initbits (&bits, ifile);
    printf ("progress: ");

    for(;;)
      {
	if (ferror(ifile))
	  {  perror ("\nRead error\n");  return (FAILURE);  }
	if (ferror(ofile))
	  {  perror ("\nWrite error\n");  return (FAILURE);  }

	if (p-data>0x4000)
	  {
	    fwrite (data,sizeof data[0],0x2000,ofile);
	    p -= 0x2000;
	    memcpy (data,data+0x2000,p-data);
	    putchar ('.');
	  }

	if (getbit(&bits))
	  {
	    *p++ = getc(ifile);
	    continue;
	  }

	if (!getbit(&bits))
	  {
	    len = getbit(&bits)<<1;
	    len |= getbit(&bits);
	    len += 2;
	    span = getc(ifile) | 0xffffff00;
	  }
	else
	  {
	    span = getc (ifile);
	    len = getc (ifile);
	    span |= ((len & ~0x07)<<5) | 0xffffe000;
	    len = (len & 0x07)+2;

	    if (len==2)
	      {
		len = getc (ifile);

		if (len==0)
		  break;	/* end mark of compreesed load module */

		if (len==1)
		  continue;	/* segment change */
		else
		  len++;
	      }
	  }
	for( ;len>0;len--,p++)
	  {
	    *p=*(p+span);
	  }
      }

    if (p!=data)
	fwrite (data, sizeof data[0], p-data, ofile);
    loadsize = ftell(ofile)-fpos;

    printf (".\n");
    return (SUCCESS);
  }


// write EXE header 
void wrhead (FILE *ofile)
  {
    if (ihead[6]!=0)
      {
	ohead[5]-= inf[5] + ((inf[6]+16-1)>>4) + 9;	// v0.7 
	if(ihead[6]!=0xffff)
		ohead[6]-=(ihead[5]-ohead[5]);
      }

    ohead[1]=((WORD)loadsize+(ohead[4]<<4)) & 0x1ff;	// v0.7 
    ohead[2]=(WORD)((loadsize+((long)ohead[4]<<4)+0x1ff) >> 9); // v0.7 

    fseek (ofile, 0L, SEEK_SET);
    fwrite (ohead, sizeof ohead[0], 0x0e, ofile);
  }



// get compress information bit by bit 
void initbits (bitstream *p, FILE *filep)
  {
    p->fp=filep;
    p->count=0x10;
    p->buf = getc(filep) + getc(filep)*256;
  }


int getbit (bitstream *p)
  {
    int b;

    b = p->buf & 1;

    if(--p->count == 0)
      {
	(p->buf) = getc(p->fp) + getc(p->fp)*256;
	p->count= 0x10;
      }
    else
	p->buf >>= 1;

    return b;
  }
