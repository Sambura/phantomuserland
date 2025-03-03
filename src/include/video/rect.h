/**
 *
 * Phantom OS
 *
 * Copyright (C) 2005-2011 Phantom OS team
 * Copyright (C) 2005-2011 Dmitry Zavalishin, dz@dz.ru
 *
 * Rectangle.
 *
**/

#ifndef VIDEO_RECT_H
#define VIDEO_RECT_H

typedef struct rect
{
    int x, y;
    int xsize, ysize;
} rect_t;

#define rect_copy( out, in ) rect_add( out, in, in )


void rect_add( rect_t *out, rect_t *a, rect_t *b );

//! Returns true if intersection exists
int rect_mul( rect_t *out, rect_t *a, rect_t *b );

//! Calculates two rectangles which together cover space which is
//! covered by old, but not covered by new. Returns nonzero if
//! out2 is not equal to out1 and not empty.
int rect_sub( rect_t *out1, rect_t *out2, rect_t *old_rect, rect_t *new_rect );

int rect_eq( rect_t *a, rect_t *b );
int rect_empty( rect_t *a );

//! Returns true if a includes (or equal to) b
int rect_includes( rect_t *a, rect_t *b );

//! Returns true if a intersects with (or equal to) b
int rect_intersects( rect_t *a, rect_t *b );


int point_in_rect( int x, int y, rect_t *r );


int rect_dump( rect_t *a );

#endif // VIDEO_RECT_H
