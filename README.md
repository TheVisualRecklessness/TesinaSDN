# SFIDPS Tesina
## Introducción
Este repositorio almacenará las diferentes versiones del script de Ryu para la detección y prevensión de intrusos en una red definida por software utilizando un switch conectado a dos hosts.

# Documentación de código

## Vista rápida
La clase `CombinedController` es una aplicación Ryu que administra switches OpenFlow. Incluye funcionalidades como administración de flujo, detección de escaneo de puerto, y bloqueo de IP.

## Constantes
- `OFP_VERSIONS`: Especifica la versión OpenFlow usada.
- `PORT_SCAN_THRESHOLD`: El número de puertos accesados por una única dirección IP dentro de la ventana de tiempo para ser considerado un escaneo de puertos.
- `TIME_WINDOW`: La ventana de tiempo en segundos para detección de escaneo de puertos.
- `FLOW_LIMIT`: El número máximo de flujos permitidos en cada switch.

## Attributes
- `mac_to_port`: Un diccionario que mapea ID's de switches a direcciones MAC a puertos.
- `scan_tracker`: Un diccionario que sigue actividades de escaneo de puertos por direcciones IP.
- `flow_counter`: Un diccionario que cuenta el número de flujos por switch.

## Métodos

### `__init__(self, *args, **kwargs)`
Inicializa el controlador, configurando las estructuras de datos necesarias.

### `switch_features_handler(self, ev)`
Maneja el evento de características del switch para configurar la primera entrada en la tabla de flujo.

### `add_flow(self, datapath, priority, match, actions, buffer_id=None)`
Añade una entrada de flujo a la tabla de flujo del switch.

### `detect_port_scan(self, src_ip, dst_port)`
Detects port scan activities by tracking accessed ports and timestamps for each source IP.
Detecta actividades de escaneo de puertos siguiendo los puertos accesados y sus tiempos para cada dirección IP origen.

### `block_ip(self, datapath, src_ip)`
Bloquea una dirección IP añadiendo una entrada de flujo de alta prioridad que desecha todos los paquetes con esa dirección IP origen.

### `_packet_in_handler(self, ev)`
Maneja paquetes entrantes, la actualización del mapeo de direcciones MAC a puertos, detección de escaneo de puertos, y envío de paquetes. 

## Manejadores de evento

### `@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)`
Maneja el evento de las características del switch para instalar la entrada de flujo inicial.

### `@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)`
Maneja paquetes entrantes, procesandolos, y toma medidas apropiadas como envío y bloqueo.

## Uso
Este controlador se usa en un entorno SDN basado en Ryu para administrar switches OpenFlow. Detecta escaneo de puertos, y bloquea direcciones IP maliciosas. También cuenta la cantidad de entradas de flujo instaladas, y una vez superado un límite, bloquea la instalación de más entradas de flujo.