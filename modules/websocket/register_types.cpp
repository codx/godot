#include "register_types.h"
#include "object_type_db.h"
#include "websocket.h"

void register_websocket_types() {
	ObjectTypeDB::register_type<Websocket>();
}

void unregister_websocket_types() {

}
