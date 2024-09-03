/**
 *
 * Phantom OS - Phantom language library
 *
**/

package .ru.dz.demo;

import .internal.string;

class garbage_unit
{
    var next : garbage_unit;
    var payload : .internal.string;

    void load_payload() {
        payload = load_existing_payload();
    }

    void set_next(var n : garbage_unit) {
        next = n;
    }

    .internal.string load_existing_payload() {
        return import "../resources/test_images/cat.jpg" ;
    }
};

