#!/bin/sh

# Set paths
SEFL_HOME=`dirname $0`
SEFL_JAR="${SEFL_HOME}/SEFloodlight.jar"
SEFL_LOGBACK="${SEFL_HOME}/logback.xml"

# Set JVM options
JVM_OPTS=""
JVM_OPTS="$JVM_OPTS -server -d64"
JVM_OPTS="$JVM_OPTS -Xmx2g -Xms2g -Xmn800m"
JVM_OPTS="$JVM_OPTS -XX:+UseParallelGC -XX:+AggressiveOpts -XX:+UseFastAccessorMethods"
JVM_OPTS="$JVM_OPTS -XX:MaxInlineSize=8192 -XX:FreqInlineSize=8192"
#JVM_OPTS="$JVM_OPTS -XX:CompileThreshold=1500 -XX:PreBlockSpin=8"
JVM_OPTS="$JVM_OPTS -XX:CompileThreshold=1500"
JVM_OPTS="$JVM_OPTS -Dpython.security.respectJavaAccessibility=false"

# Create a logback file if required
[ -f ${SEFL_LOGBACK} ] || cat <<EOF_LOGBACK >${SEFL_LOGBACK}
<configuration scan="true">
    <appender name="STDOUT" class="ch.qos.logback.core.ConsoleAppender">
        <encoder>
            <pattern>%date{yyyy-MM-dd HH:mm:ss.S} %-5level [%logger{15}:%thread] %msg%n</pattern>
        </encoder>
    </appender>
    <root level="INFO">
        <appender-ref ref="STDOUT" />
    </root>
    <logger name="org" level="WARN"/>
    <logger name="LogService" level="WARN"/> <!-- Restlet access logging -->
    <logger name="net.floodlightcontroller" level="INFO"/>
    <logger name="net.floodlightcontroller.logging" level="ERROR"/>
</configuration>
EOF_LOGBACK

echo "Starting security enhanced floodlight server ..."
java ${JVM_OPTS} -Dlogback.configurationFile=${SEFL_LOGBACK} -jar ${SEFL_JAR}
