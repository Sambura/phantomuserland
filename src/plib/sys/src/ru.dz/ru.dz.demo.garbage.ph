/**
 *
 * Phantom OS - Phantom language library
 *
**/

package .ru.dz.demo;

import .phantom.os;
import .internal.io.tty;
import .internal.string;
import .internal.connection;
import .ru.dz.demo.garbage_unit;

class garbage
{
    void run(var console : .internal.io.tty)
    {
        console.putws("Started garbage generation demo scenario\n");

        var sleep : .internal.connection;
        sleep = new .internal.connection();
        sleep.connect("tmr:");

        var garbage_created : .internal.int;
        garbage_created = 0;
        while (1) {
            var A : garbage_unit;
            var B : garbage_unit;
            var C : garbage_unit;
            A = new garbage_unit();
            B = new garbage_unit();
            C = new garbage_unit();

            A.load_payload();
            A.set_next(B);
            B.set_next(C);
            C.set_next(A);

            garbage_created = garbage_created + 3;
            console.putws("Iteration complete, total garbage created: ");
            console.putws(garbage_created.toString());
            console.putws("\n");
            sleep.block(null, 25);
        }
    }
};

