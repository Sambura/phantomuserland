/**
 *
 * Phantom OS - Phantom language library
 *
 * Copyright (C) 2005-2009 Dmitry Zavalishin, dz@dz.ru
 *
 * Simple demo
 *
 *
**/

package .ru.dz.demo;

import .phantom.os;
import .internal.io.tty;

import .ru.dz.phantom.performance_test;
import .ru.dz.phantom.persistence_test;
import .ru.dz.demo.weather;
import .ru.dz.demo.chart;
import .ru.dz.demo.wasm;
import .ru.dz.demo.garbage;

attribute const * ->!;


class start
{
    var demo : .ru.dz.demo.garbage;
    // var demo : .ru.dz.demo.weather;
    // var demo : .ru.dz.demo.wasm;

    void run(var console : .internal.io.tty)
    {
        // demo = new  .ru.dz.demo.weather();
        demo = new  .ru.dz.demo.garbage();
        demo.run(console);
    }
};
