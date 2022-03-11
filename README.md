# arpd

ARP Daemon in Java. Open Source project under Apache License v2.0

---

## DOC

#### Usage Example (command line)

    java -cp conf/:lib/arpd-2.0.1.jar:lib/pcap4j-core-1.8.2.jar:lib/pcap4j-packetfactory-static-1.8.2.jar:lib/jna-5.3.1.jar:lib/slf4j-api-1.7.36.jar:lib/slf4j-reload4j-1.7.36.jar:lib/reload4j-1.2.19.jar \
         -Darpd.home=/opt/arpd \
         -Darpd.keepalive=/opt/arpd/arpd.alive \
         -Darpd.runfile=/opt/arpd/arpd.run \
         -Darpd.status=/opt/arpd/arpd.status \
         -Dlog.out=console -Dlog.name=arpd \
         org.javastack.arpd.ARPD conf/arpd.conf

#### Sample conf/arpd.conf

```properties
# Basic syntax:
# [-]ip[/cidr] device

# x.x.x.x = included
# -x.x.x.x = excluded
# [-]x.x.x.x = ip
# [-]x.x.x.x/cidr = net/bits

# Exclude Gateway IP
-192.168.1.1 eth0
# Include Network
192.168.1.0/24 eth0
```

#### Sample conf/log4j.properties

```properties
## Root Logger ##
log4j.rootLogger=INFO, ${log.out}, std

## Application ##
log4j.logger.ARPD=TRACE, ${log.out}, std, trace
log4j.additivity.ARPD=false

## Null Appender ##
log4j.appender.null=org.apache.log4j.varia.NullAppender

## Console Appender ##
log4j.appender.console=org.apache.log4j.ConsoleAppender
log4j.appender.console.layout=org.apache.log4j.PatternLayout
log4j.appender.console.layout.ConversionPattern=%-4r [%t] %-5p %c %x - %m%n

## Standard Log ##
log4j.appender.std=org.apache.log4j.DailyRollingFileAppender
log4j.appender.std.append=true
log4j.appender.std.Threshold=INFO
log4j.appender.std.file=${arpd.home}/log/${log.name}.log
log4j.appender.std.DatePattern='.'yyyy-MM-dd
log4j.appender.std.layout=org.apache.log4j.PatternLayout
log4j.appender.std.layout.ConversionPattern=[%p] %C %d{dd/MM/yyyy HH:mm:ss} - %m%n

## Trace Log ##
log4j.appender.trace=org.apache.log4j.RollingFileAppender
log4j.appender.trace.MaxFileSize=1MB
log4j.appender.trace.MaxBackupIndex=3
log4j.appender.trace.append=true
log4j.appender.trace.file=${arpd.home}/log/${log.name}-trace.log
log4j.appender.trace.layout=org.apache.log4j.PatternLayout
log4j.appender.trace.layout.ConversionPattern=[%p] %C %d{dd/MM/yyyy HH:mm:ss} - %m%n
```

---
Inspired in [arpd](https://linux.die.net/man/8/arpd), this code is Java-minimalistic version.
