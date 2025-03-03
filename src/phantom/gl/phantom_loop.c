/*
 * Demonstration program for Phantom OS
 */

#include <phantom_libc.h>

//// #include <stdio.h>
#include <stdlib.h>
#include <ph_string.h>
#include "ui.h"

//#include "drv_video_screen.h"
#include "tinyphantom.h"

#include <ph_malloc.h>
#include <ph_os.h>

//static	GR_WINDOW_ID	w1;		/* id for large window */
//static	GR_GC_ID	gc1;		/* graphics context for text */

window_handle_t w1;

void errorcatcher();			/* routine to handle errors */

void tkSwapBuffers(void)
{
    PhantomSwapBuffers(w1);
}

/* change view angle, exit upon ESC */
GLenum key(int k, GLenum mask)
{
    switch (k) {
    case 'q':
    case KEY_ESCAPE:
        exit(0);
    }
    return GL_FALSE;
}

int
ui_loop(int argc,char **argv, const char *name)
{
	//GR_EVENT	event;		/* current event */
	//GR_IMAGE_ID	id = 0;
        //NGLXContext cx;
        int width, height;

        /*
	if (GrOpen() < 0) {
		ph_printf("cannot open graphics\n");
		exit(1);
	}*/
	
        width = 400;
        height = 300;

        w1 = ph_malloc(drv_video_window_bytes(width,height));
        w1->xsize = width;
        w1->ysize = height;

        TinyPhantomContext *cx = PhantomCreateContext(0);
        PhantomMakeCurrent(w1, cx);
        
        init();
        reshape(width, height);

	while (1) {

            // if no char
            //                idle();
            idle();
#if 0
            int k;

            continue;
            int c = getchar();
            ph_printf("ph_loop ");
            switch(c)
            {
            case 0x1B:
                exit(0);

            case 'l':                        k = KEY_LEFT;      break;
            case 'r':                        k = KEY_RIGHT;	break;
            case 'u':                        k = KEY_UP;	break;
            case 'd':                        k = KEY_DOWN;	break;
            default:
                k = c;
                break;
            }
            key(k, 0);
#endif
        }
	return 0;
}


/*
 * Here on an unrecoverable error.
 * /
void
errorcatcher(code, name, id)
	GR_ERROR	code;		// error code
	GR_FUNC_NAME	name;		// function name which failed
	GR_ID		id;		// resource id
{
	GrClose();
	fprintf(stderr, "DEMO ERROR: code %d, function %s, resource id %d\n",
		code, name, id);
	exit(1);
}  */
