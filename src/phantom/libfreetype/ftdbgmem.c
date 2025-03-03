/***************************************************************************/
/*                                                                         */
/*  ftdbgmem.c                                                             */
/*                                                                         */
/*    Memory debugger (body).                                              */
/*                                                                         */
/*  Copyright 2001, 2002, 2003, 2004, 2005 by                              */
/*  David Turner, Robert Wilhelm, and Werner Lemberg.                      */
/*                                                                         */
/*  This file is part of the FreeType project, and may only be used,       */
/*  modified, and distributed under the terms of the FreeType project      */
/*  license, LICENSE.TXT.  By continuing to use, modify, or distribute     */
/*  this file you indicate that you have read the license and              */
/*  understand and accept it fully.                                        */
/*                                                                         */
/***************************************************************************/


#include <ft2build.h>
#include FT_CONFIG_CONFIG_H
#include FT_INTERNAL_DEBUG_H
#include FT_INTERNAL_MEMORY_H
#include FT_SYSTEM_H
#include FT_ERRORS_H
#include FT_TYPES_H


#ifdef FT_DEBUG_MEMORY

#define  KEEPALIVE /* `Keep alive' means that freed blocks aren't released
                    * to the heap.  This is useful to detect double-frees
                    * or weird heap corruption, but it uses large amounts of
                    * memory, however.
                    */

// #include <stdio.h>
#include <stdlib.h>


  extern void
  FT_DumpMemory( FT_Memory  memory );


  typedef struct FT_MemSourceRec_*  FT_MemSource;
  typedef struct FT_MemNodeRec_*    FT_MemNode;
  typedef struct FT_MemTableRec_*   FT_MemTable;


#define FT_MEM_VAL( addr )  ((FT_ULong)(FT_Pointer)( addr ))


  typedef struct FT_MemSourceRec_
  {
    const char*   file_name;
    long          line_no;

    FT_Long       cur_blocks;   /* current number of allocated blocks */
    FT_Long       max_blocks;   /* max. number of allocated blocks    */
    FT_Long       all_blocks;   /* total number of blocks allocated   */

    FT_Long       cur_size;     /* current cumulative allocated size */
    FT_Long       max_size;     /* maximum cumulative allocated size */
    FT_Long       all_size;     /* total cumulative allocated size   */

    FT_Long       cur_max;      /* current maximum allocated size */

    FT_UInt32     hash;
    FT_MemSource  link;

  } FT_MemSourceRec;


/*
 *  We don't need a resizable array for the memory sources, because
 *  their number is pretty limited within FreeType.
 */
#define FT_MEM_SOURCE_BUCKETS  128


  typedef struct  FT_MemNodeRec_
  {
    FT_Byte*      address;
    FT_Long       size;     /* < 0 if the block was freed */

    FT_MemSource  source;

#ifdef KEEPALIVE
    const char*   free_file_name;
    FT_Long       free_line_no;
#endif

    FT_MemNode    link;

  } FT_MemNodeRec;


  typedef struct  FT_MemTableRec_
  {
    FT_ULong         size;
    FT_ULong         nodes;
    FT_MemNode*      buckets;

    FT_ULong         alloc_total;
    FT_ULong         alloc_current;
    FT_ULong         alloc_max;
    FT_ULong         alloc_count;

    FT_Bool          bound_total;
    FT_ULong         alloc_total_max;

    FT_Bool          bound_count;
    FT_ULong         alloc_count_max;

    FT_MemSource     sources[FT_MEM_SOURCE_BUCKETS];

    const char*      file_name;
    FT_Long          line_no;

    FT_Bool          keep_alive;

    FT_Memory        memory;
    FT_Pointer       memory_user;
    FT_Alloc_Func    alloc;
    FT_Free_Func     free;
    FT_Realloc_Func  realloc;

  } FT_MemTableRec;


#define FT_MEM_SIZE_MIN  7
#define FT_MEM_SIZE_MAX  13845163

#define FT_FILENAME( x )  ((x) ? (x) : "unknown file")

#define EXIT_FAILURE	-1


 /*
  *  Prime numbers are ugly to handle.  It would be better to implement
  *  L-Hashing, which is 10% faster and doesn't require divisions.
  */
  static const FT_UInt  ft_mem_primes[] =
  {
    7,
    11,
    19,
    37,
    73,
    109,
    163,
    251,
    367,
    557,
    823,
    1237,
    1861,
    2777,
    4177,
    6247,
    9371,
    14057,
    21089,
    31627,
    47431,
    71143,
    106721,
    160073,
    240101,
    360163,
    540217,
    810343,
    1215497,
    1823231,
    2734867,
    4102283,
    6153409,
    9230113,
    13845163,
  };


  static FT_ULong
  ft_mem_closest_prime( FT_ULong  num )
  {
    FT_UInt  i;


    for ( i = 0;
          i < sizeof ( ft_mem_primes ) / sizeof ( ft_mem_primes[0] ); i++ )
      if ( ft_mem_primes[i] > num )
        return ft_mem_primes[i];

    return FT_MEM_SIZE_MAX;
  }


  extern void
  ft_mem_debug_panic( const char*  fmt,
                      ... )
  {
    va_list  ap;


    ph_printf( "FreeType.Debug: " );

    va_start( ap, fmt );
    ph_vprintf( fmt, ap );
    va_end( ap );

    ph_printf( "\n" );
    exit( EXIT_FAILURE );
  }


  static FT_Pointer
  ft_mem_table_alloc( FT_MemTable  table,
                      FT_Long      size )
  {
    FT_Memory   memory = table->memory;
    FT_Pointer  block;


    memory->user = table->memory_user;
    block = table->alloc( memory, size );
    memory->user = table;

   return block;
  }


  static void
  ft_mem_table_free( FT_MemTable  table,
                     FT_Pointer   block )
  {
    FT_Memory  memory = table->memory;


    memory->user = table->memory_user;
    table->free( memory, block );
    memory->user = table;
  }


  static void
  ft_mem_table_resize( FT_MemTable  table )
  {
    FT_ULong  new_size;


    new_size = ft_mem_closest_prime( table->nodes );
    if ( new_size != table->size )
    {
      FT_MemNode*  new_buckets;
      FT_ULong     i;


      new_buckets = (FT_MemNode *)
                      ft_mem_table_alloc( table,
                                          new_size * sizeof ( FT_MemNode ) );
      if ( new_buckets == NULL )
        return;

      FT_ARRAY_ZERO( new_buckets, new_size );

      for ( i = 0; i < table->size; i++ )
      {
        FT_MemNode  node, next, *pnode;
        FT_ULong    hash;


        node = table->buckets[i];
        while ( node )
        {
          next  = node->link;
          hash  = FT_MEM_VAL( node->address ) % new_size;
          pnode = new_buckets + hash;

          node->link = pnode[0];
          pnode[0]   = node;

          node = next;
        }
      }

      if ( table->buckets )
        ft_mem_table_free( table, table->buckets );

      table->buckets = new_buckets;
      table->size    = new_size;
    }
  }


  static FT_MemTable
  ft_mem_table_new( FT_Memory  memory )
  {
    FT_MemTable  table;


    table = (FT_MemTable)memory->alloc( memory, sizeof ( *table ) );
    if ( table == NULL )
      goto Exit;

    FT_ZERO( table );

    table->size  = FT_MEM_SIZE_MIN;
    table->nodes = 0;

    table->memory = memory;

    table->memory_user = memory->user;

    table->alloc   = memory->alloc;
    table->realloc = memory->realloc;
    table->free    = memory->free;

    table->buckets = (FT_MemNode *)
                       memory->alloc( memory,
                                      table->size * sizeof ( FT_MemNode ) );
    if ( table->buckets )
      FT_ARRAY_ZERO( table->buckets, table->size );
    else
    {
      memory->free( memory, table );
      table = NULL;
    }

  Exit:
    return table;
  }


  static void
  ft_mem_table_destroy( FT_MemTable  table )
  {
    FT_ULong  i;


    FT_DumpMemory( table->memory );

    if ( table )
    {
      FT_Long    leak_count = 0;
      FT_ULong   leaks = 0;

      /* remove all blocks from the table, revealing leaked ones */
      for ( i = 0; i < table->size; i++ )
      {
        FT_MemNode  *pnode = table->buckets + i, next, node = *pnode;


        while ( node )
        {
          next       = node->link;
          node->link = 0;

          if ( node->size > 0 )
          {
            ph_printf(
              "leaked memory block at address %p, size %8ld in (%s:%ld)\n",
              node->address, node->size,
              FT_FILENAME( node->source->file_name ),
              node->source->line_no );

            leak_count++;
            leaks += node->size;

            ft_mem_table_free( table, node->address );
          }

          node->address = NULL;
          node->size    = 0;

          ft_mem_table_free( table, node );
          node = next;
        }
        table->buckets[i] = 0;
      }

      ft_mem_table_free( table, table->buckets );
      table->buckets = NULL;

      table->size   = 0;
      table->nodes  = 0;

      /* remove all sources */
      for ( i = 0; i < FT_MEM_SOURCE_BUCKETS; i++ )
      {
        FT_MemSource  source, next;


        for ( source = table->sources[i]; source != NULL; source = next )
        {
          next = source->link;
          ft_mem_table_free( table, source );
        }

        table->sources[i] = NULL;
      }

      ph_printf(
        "FreeType: total memory allocations = %ld\n", table->alloc_total );
      ph_printf(
        "FreeType: maximum memory footprint = %ld\n", table->alloc_max );

      ft_mem_table_free( table, table );

      if ( leak_count > 0 )
        ft_mem_debug_panic(
          "FreeType: %ld bytes of memory leaked in %ld blocks\n",
          leaks, leak_count );

      ph_printf( "FreeType: No memory leaks detected!\n" );
    }
  }


  static FT_MemNode*
  ft_mem_table_get_nodep( FT_MemTable  table,
                          FT_Byte*     address )
  {
    FT_ULong     hash;
    FT_MemNode  *pnode, node;


    hash  = FT_MEM_VAL( address );
    pnode = table->buckets + ( hash % table->size );

    for (;;)
    {
      node = pnode[0];
      if ( !node )
        break;

      if ( node->address == address )
        break;

      pnode = &node->link;
    }
    return pnode;
  }


  static FT_MemSource
  ft_mem_table_get_source( FT_MemTable  table )
  {
    FT_UInt32     hash;
    FT_MemSource  node, *pnode;


    hash  = (FT_UInt32)(void*)table->file_name +
              (FT_UInt32)( 5 * table->line_no );
    pnode = &table->sources[hash % FT_MEM_SOURCE_BUCKETS];

    for ( ;; )
    {
      node = *pnode;
      if ( node == NULL )
        break;

      if ( node->file_name == table->file_name &&
           node->line_no   == table->line_no   )
        goto Exit;

      pnode = &node->link;
    }

    node = (FT_MemSource)ft_mem_table_alloc( table, sizeof ( *node ) );
    if ( node == NULL )
      ft_mem_debug_panic(
        "not enough memory to perform memory debugging\n" );

    node->file_name = table->file_name;
    node->line_no   = table->line_no;

    node->cur_blocks = 0;
    node->max_blocks = 0;
    node->all_blocks = 0;

    node->cur_size   = 0;
    node->max_size   = 0;
    node->all_size   = 0;

    node->cur_max    = 0;

    node->link = NULL;
    node->hash = hash;
    *pnode     = node;

  Exit:
    return node;
  }


  static void
  ft_mem_table_set( FT_MemTable  table,
                    FT_Byte*     address,
                    FT_ULong     size )
  {
    FT_MemNode  *pnode, node;


    if ( table )
    {
      FT_MemSource  source;


      pnode = ft_mem_table_get_nodep( table, address );
      node  = *pnode;
      if ( node )
      {
        if ( node->size < 0 )
        {
          /* This block was already freed.  Our memory is now completely */
          /* corrupted!                                                  */
          /* This can only happen in keep-alive mode.                    */
          ft_mem_debug_panic(
            "memory heap corrupted (allocating freed block)" );
        }
        else
        {
          /* This block was already allocated.  This means that our memory */
          /* is also corrupted!                                            */
          ft_mem_debug_panic(
            "memory heap corrupted (re-allocating allocated block at"
            " %p, of size %ld)\n"
            "org=%s:%d new=%s:%d\n",
            node->address, node->size,
            FT_FILENAME( node->source->file_name ), node->source->line_no,
            FT_FILENAME( table->file_name ), table->line_no );
        }
      }

      /* we need to create a new node in this table */
      node = (FT_MemNode)ft_mem_table_alloc( table, sizeof ( *node ) );
      if ( node == NULL )
        ft_mem_debug_panic( "not enough memory to run memory tests" );

      node->address = address;
      node->size    = size;

      node->source = source = ft_mem_table_get_source( table );

      source->all_blocks++;
      source->cur_blocks++;
      if ( source->cur_blocks > source->max_blocks )
        source->max_blocks = source->cur_blocks;

      if ( size > (FT_ULong)source->cur_max )
        source->cur_max = size;

      source->all_size += size;
      source->cur_size += size;
      if ( source->cur_size > source->max_size )
        source->max_size = source->cur_size;

      node->free_file_name = NULL;
      node->free_line_no   = 0;

      node->link = pnode[0];

      pnode[0] = node;
      table->nodes++;

      table->alloc_total   += size;
      table->alloc_current += size;
      if ( table->alloc_current > table->alloc_max )
        table->alloc_max = table->alloc_current;

      if ( table->nodes * 3 < table->size  ||
           table->size  * 3 < table->nodes )
        ft_mem_table_resize( table );
    }
  }


  static void
  ft_mem_table_remove( FT_MemTable  table,
                       FT_Byte*     address )
  {
    if ( table )
    {
      FT_MemNode  *pnode, node;


      pnode = ft_mem_table_get_nodep( table, address );
      node  = *pnode;
      if ( node )
      {
        FT_MemSource  source;


        if ( node->size < 0 )
          ft_mem_debug_panic(
            "freeing memory block at %p more than once at (%s:%ld)\n"
            "block allocated at (%s:%ld) and released at (%s:%ld)",
            address,
            FT_FILENAME( table->file_name ), table->line_no,
            FT_FILENAME( node->source->file_name ), node->source->line_no,
            FT_FILENAME( node->free_file_name ), node->free_line_no );

        /* scramble the node's content for additional safety */
        FT_MEM_SET( address, 0xF3, node->size );
        table->alloc_current -= node->size;

        source = node->source;

        source->cur_blocks--;
        source->cur_size -= node->size;

        if ( table->keep_alive )
        {
          /* we simply invert the node's size to indicate that the node */
          /* was freed.                                                 */
          node->size           = -node->size;
          node->free_file_name = table->file_name;
          node->free_line_no   = table->line_no;
        }
        else
        {
          table->nodes--;

          *pnode = node->link;

          node->size   = 0;
          node->source = NULL;

          ft_mem_table_free( table, node );

          if ( table->nodes * 3 < table->size  ||
               table->size  * 3 < table->nodes )
            ft_mem_table_resize( table );
        }
      }
      else
        ft_mem_debug_panic(
          "trying to free unknown block at %p in (%s:%ld)\n",
          address,
          FT_FILENAME( table->file_name ), table->line_no );
    }
  }


  extern FT_Pointer
  ft_mem_debug_alloc( FT_Memory  memory,
                      FT_Long    size )
  {
    FT_MemTable  table = (FT_MemTable)memory->user;
    FT_Byte*     block;


    if ( size <= 0 )
      ft_mem_debug_panic( "negative block size allocation (%ld)", size );

    /* return NULL if the maximum number of allocations was reached */
    if ( table->bound_count                           &&
         table->alloc_count >= table->alloc_count_max )
      return NULL;

    /* return NULL if this allocation would overflow the maximum heap size */
    if ( table->bound_total                                             &&
         table->alloc_current + (FT_ULong)size > table->alloc_total_max )
      return NULL;

    block = (FT_Byte *)ft_mem_table_alloc( table, size );
    if ( block )
      ft_mem_table_set( table, block, (FT_ULong)size );

    table->alloc_count++;

    table->file_name = NULL;
    table->line_no   = 0;

    return (FT_Pointer)block;
  }


  extern void
  ft_mem_debug_free( FT_Memory   memory,
                     FT_Pointer  block )
  {
    FT_MemTable  table = (FT_MemTable)memory->user;


    if ( block == NULL )
      ft_mem_debug_panic( "trying to free NULL in (%s:%ld)",
                          FT_FILENAME( table->file_name ),
                          table->line_no );

    ft_mem_table_remove( table, (FT_Byte*)block );

    if ( !table->keep_alive )
      ft_mem_table_free( table, block );

    table->alloc_count--;

    table->file_name = NULL;
    table->line_no   = 0;
  }


  extern FT_Pointer
  ft_mem_debug_realloc( FT_Memory   memory,
                        FT_Long     cur_size,
                        FT_Long     new_size,
                        FT_Pointer  block )
  {
    FT_MemTable  table = (FT_MemTable)memory->user;
    FT_MemNode   node, *pnode;
    FT_Pointer   new_block;

    const char*  file_name = FT_FILENAME( table->file_name );
    FT_Long      line_no   = table->line_no;


    /* the following is valid according to ANSI C */
#if 0
    if ( block == NULL || cur_size == 0 )
      ft_mem_debug_panic( "trying to reallocate NULL in (%s:%ld)",
                          file_name, line_no );
#endif

    /* while the following is allowed in ANSI C also, we abort since */
    /* such case should be handled by FreeType.                      */
    if ( new_size <= 0 )
      ft_mem_debug_panic(
        "trying to reallocate %p to size 0 (current is %ld) in (%s:%ld)",
        block, cur_size, file_name, line_no );

    /* check `cur_size' value */
    pnode = ft_mem_table_get_nodep( table, (FT_Byte*)block );
    node  = *pnode;
    if ( !node )
      ft_mem_debug_panic(
        "trying to reallocate unknown block at %p in (%s:%ld)",
        block, file_name, line_no );

    if ( node->size <= 0 )
      ft_mem_debug_panic(
        "trying to reallocate freed block at %p in (%s:%ld)",
        block, file_name, line_no );

    if ( node->size != cur_size )
      ft_mem_debug_panic( "invalid ft_realloc request for %p. cur_size is "
                          "%ld instead of %ld in (%s:%ld)",
                          block, cur_size, node->size, file_name, line_no );

    new_block = ft_mem_debug_alloc( memory, new_size );
    if ( new_block == NULL )
      return NULL;

    ft_memcpy( new_block, block, cur_size < new_size ? cur_size : new_size );

    table->file_name = file_name;
    table->line_no   = line_no;

    ft_mem_debug_free( memory, (FT_Byte*)block );

    return new_block;
  }


  extern FT_Int
  ft_mem_debug_init( FT_Memory  memory )
  {
    FT_MemTable  table;
    FT_Int       result = 0;


    if ( getenv( "FT2_DEBUG_MEMORY" ) )
    {
      table = ft_mem_table_new( memory );
      if ( table )
      {
        const char*  p;


        memory->user    = table;
        memory->alloc   = ft_mem_debug_alloc;
        memory->realloc = ft_mem_debug_realloc;
        memory->free    = ft_mem_debug_free;

        p = getenv( "FT2_ALLOC_TOTAL_MAX" );
        if ( p != NULL )
        {
          FT_Long   total_max = ft_atol( p );


          if ( total_max > 0 )
          {
            table->bound_total     = 1;
            table->alloc_total_max = (FT_ULong)total_max;
          }
        }

        p = getenv( "FT2_ALLOC_COUNT_MAX" );
        if ( p != NULL )
        {
          FT_Long  total_count = ft_atol( p );


          if ( total_count > 0 )
          {
            table->bound_count     = 1;
            table->alloc_count_max = (FT_ULong)total_count;
          }
        }

        p = getenv( "FT2_KEEP_ALIVE" );
        if ( p != NULL )
        {
          FT_Long  keep_alive = ft_atol( p );


          if ( keep_alive > 0 )
            table->keep_alive = 1;
        }

        result = 1;
      }
    }
    return result;
  }


  extern void
  ft_mem_debug_done( FT_Memory  memory )
  {
    FT_MemTable  table = (FT_MemTable)memory->user;


    if ( table )
    {
      memory->free    = table->free;
      memory->realloc = table->realloc;
      memory->alloc   = table->alloc;

      ft_mem_table_destroy( table );
      memory->user = NULL;
    }
  }


  FT_BASE_DEF( FT_Error )
  FT_Alloc_Debug( FT_Memory    memory,
                  FT_Long      size,
                  void*       *P,
                  const char*  file_name,
                  FT_Long      line_no )
  {
    FT_MemTable  table = (FT_MemTable)memory->user;


    if ( table )
    {
      table->file_name = file_name;
      table->line_no   = line_no;
    }

    return FT_Alloc( memory, size, P );
  }


  FT_BASE_DEF( FT_Error )
  FT_Realloc_Debug( FT_Memory    memory,
                    FT_Long      current,
                    FT_Long      size,
                    void*       *P,
                    const char*  file_name,
                    FT_Long      line_no )
  {
    FT_MemTable  table = (FT_MemTable)memory->user;


    if ( table )
    {
      table->file_name = file_name;
      table->line_no   = line_no;
    }

    return FT_Realloc( memory, current, size, P );
  }


  FT_BASE_DEF( FT_Error )
  FT_QAlloc_Debug( FT_Memory    memory,
                   FT_Long      size,
                   void*       *P,
                   const char*  file_name,
                   FT_Long      line_no )
  {
    FT_MemTable  table = (FT_MemTable)memory->user;


    if ( table )
    {
      table->file_name = file_name;
      table->line_no   = line_no;
    }

    return FT_QAlloc( memory, size, P );
  }


  FT_BASE_DEF( FT_Error )
  FT_QRealloc_Debug( FT_Memory    memory,
                     FT_Long      current,
                     FT_Long      size,
                     void*       *P,
                     const char*  file_name,
                     FT_Long      line_no )
  {
    FT_MemTable  table = (FT_MemTable)memory->user;


    if ( table )
    {
      table->file_name = file_name;
      table->line_no   = line_no;
    }

    return FT_QRealloc( memory, current, size, P );
  }


  FT_BASE_DEF( void )
  FT_Free_Debug( FT_Memory    memory,
                 FT_Pointer   block,
                 const char*  file_name,
                 FT_Long      line_no )
  {
    FT_MemTable  table = (FT_MemTable)memory->user;


    if ( table )
    {
      table->file_name = file_name;
      table->line_no   = line_no;
    }

    FT_Free( memory, (void **)block );
  }


  static int
  ft_mem_source_compare( const void*  p1,
                         const void*  p2 )
  {
    FT_MemSource  s1 = *(FT_MemSource*)p1;
    FT_MemSource  s2 = *(FT_MemSource*)p2;


    if ( s2->max_size > s1->max_size )
      return 1;
    else if ( s2->max_size < s1->max_size )
      return -1;
    else
      return 0;
  }


  extern void
  FT_DumpMemory( FT_Memory  memory )
  {
    FT_MemTable  table = (FT_MemTable)memory->user;


    if ( table )
    {
      FT_MemSource*  bucket = table->sources;
      FT_MemSource*  limit  = bucket + FT_MEM_SOURCE_BUCKETS;
      FT_MemSource*  sources;
      FT_UInt        nn, count;
      const char*    fmt;


      count = 0;
      for ( ; bucket < limit; bucket++ )
      {
        FT_MemSource  source = *bucket;


        for ( ; source; source = source->link )
          count++;
      }

      sources = (FT_MemSource*)ft_mem_table_alloc(
                                 table, sizeof ( *sources ) * count );

      count = 0;
      for ( bucket = table->sources; bucket < limit; bucket++ )
      {
        FT_MemSource  source = *bucket;


        for ( ; source; source = source->link )
          sources[count++] = source;
      }

      ft_qsort( sources, count, sizeof ( *sources ), ft_mem_source_compare );

      ph_printf( "FreeType Memory Dump: "
              "current=%ld max=%ld total=%ld count=%ld\n",
              table->alloc_current, table->alloc_max,
              table->alloc_total, table->alloc_count );
      ph_printf( " block  block    sizes    sizes    sizes   source\n" );
      ph_printf( " count   high      sum  highsum      max   location\n" );
      ph_printf( "-------------------------------------------------\n" );

      fmt = "%6ld %6ld %8ld %8ld %8ld %s:%d\n";

      for ( nn = 0; nn < count; nn++ )
      {
        FT_MemSource  source = sources[nn];


        ph_printf( fmt,
                source->cur_blocks, source->max_blocks,
                source->cur_size, source->max_size, source->cur_max,
                FT_FILENAME( source->file_name ),
                source->line_no );
      }
      ph_printf( "------------------------------------------------\n" );

      ft_mem_table_free( table, sources );
    }
  }

#else  /* !FT_DEBUG_MEMORY */

  /* ANSI C doesn't like empty source files */
  const FT_Byte  _debug_mem_dummy = 0;

#endif /* !FT_DEBUG_MEMORY */


/* END */
