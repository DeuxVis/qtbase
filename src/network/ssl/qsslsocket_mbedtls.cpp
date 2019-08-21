/****************************************************************************
**
** Copyright (C) 2019 The Qt Company Ltd.
** Contact: https://www.qt.io/licensing/
**
** This file is part of the QtNetwork module of the Qt Toolkit.
**
** $QT_BEGIN_LICENSE:LGPL$
** Commercial License Usage
** Licensees holding valid commercial Qt licenses may use this file in
** accordance with the commercial license agreement provided with the
** Software or, alternatively, in accordance with the terms contained in
** a written agreement between you and The Qt Company. For licensing terms
** and conditions see https://www.qt.io/terms-conditions. For further
** information use the contact form at https://www.qt.io/contact-us.
**
** GNU Lesser General Public License Usage
** Alternatively, this file may be used under the terms of the GNU Lesser
** General Public License version 3 as published by the Free Software
** Foundation and appearing in the file LICENSE.LGPL3 included in the
** packaging of this file. Please review the following information to
** ensure the GNU Lesser General Public License version 3 requirements
** will be met: https://www.gnu.org/licenses/lgpl-3.0.html.
**
** GNU General Public License Usage
** Alternatively, this file may be used under the terms of the GNU
** General Public License version 2.0 or (at your option) the GNU General
** Public license version 3 or any later version approved by the KDE Free
** Qt Foundation. The licenses are as published by the Free Software
** Foundation and appearing in the file LICENSE.GPL2 and LICENSE.GPL3
** included in the packaging of this file. Please review the following
** information to ensure the GNU General Public License requirements will
** be met: https://www.gnu.org/licenses/gpl-2.0.html and
** https://www.gnu.org/licenses/gpl-3.0.html.
**
** $QT_END_LICENSE$
**
****************************************************************************/

#include "qsslsocket_mbedtls_p.h"
#include "qsslcipher_p.h"


#include <mbedtls/version.h>
#include <mbedtls/error.h>
#include <mbedtls/debug.h>
#include <mbedtls/platform.h>

#include <QtCore/qdir.h>
#include <QtCore/qdiriterator.h>

#include <unistd.h>


QT_BEGIN_NAMESPACE

Q_LOGGING_CATEGORY(catQSslSocketBackendPrivate, "QSslSocketBackendPrivate");

#define MBEDTLS_DEBUG_LEVEL 0

bool QSslSocketPrivate::s_libraryLoaded = true;
bool QSslSocketPrivate::s_loadRootCertsOnDemand = true;
bool QSslSocketPrivate::s_loadedCiphersAndCerts = false;



static void our_debug( void *ctx, int level, const char *file, int line, const char *str )
{
    ((void) level);

    mbedtls_fprintf( (FILE *) ctx, "%s:%04d: %s", file, line, str );
    fflush(  (FILE *) ctx  );
}

void QSslSocketPrivate::ensureInitialized()
{
    if (s_loadedCiphersAndCerts)
        return;

    s_loadedCiphersAndCerts = true;
    resetDefaultCiphers();
}

void QSslSocketPrivate::resetDefaultCiphers()
{
    setDefaultSupportedCiphers(QSslSocketBackendPrivate::defaultCiphers());
    setDefaultCiphers(QSslSocketBackendPrivate::defaultCiphers());
}

QList<QSslCertificate> QSslSocketPrivate::systemCaCertificates()
{
    QList<QSslCertificate> systemCaCerts;
    QStringList nameFilters;
    nameFilters << QLatin1String("*.pem") << QLatin1String("*.crt");
    QList<QByteArray> directories = unixRootCertDirectories();
    QSsl::EncodingFormat platformEncodingFormat = QSsl::Pem;
    QDir currentDir;
    currentDir.setNameFilters(nameFilters);
    QSet<QString> certFiles;
    
    for (int a = 0; a < directories.count(); a++)
    {
        currentDir.setPath(QLatin1String(directories.at(a)));
        QDirIterator it(currentDir);
        while (it.hasNext())
        {
            it.next();
            certFiles.insert(it.fileInfo().canonicalFilePath());
        }
    }
    for (const QString& file : qAsConst(certFiles))
        systemCaCerts.append(QSslCertificate::fromPath(file, platformEncodingFormat));

    systemCaCerts.append(QSslCertificate::fromPath(QLatin1String("/etc/pki/tls/certs/ca-bundle.crt"), QSsl::Pem)); // Fedora, Mandriva
    systemCaCerts.append(QSslCertificate::fromPath(QLatin1String("/usr/local/share/certs/ca-root-nss.crt"), QSsl::Pem)); // FreeBSD's ca_root_nss
    
    return systemCaCerts;
}

long QSslSocketPrivate::sslLibraryVersionNumber()
{
    return MBEDTLS_VERSION_NUMBER;
}

QString QSslSocketPrivate::sslLibraryVersionString()
{
    return QStringLiteral(MBEDTLS_VERSION_STRING_FULL);
}

long QSslSocketPrivate::sslLibraryBuildVersionNumber()
{
    return sslLibraryVersionNumber();
}

QString QSslSocketPrivate::sslLibraryBuildVersionString()
{
    return sslLibraryVersionString();
}

bool QSslSocketPrivate::supportsSsl()
{
    return true;
}


QSslSocketBackendPrivate::QSslSocketBackendPrivate()
{
    if (MBEDTLS_DEBUG_LEVEL)
        qCWarning(catQSslSocketBackendPrivate, "Entering QSslSocketBackendPrivate()");
        
    Q_Q(QSslSocket);
    
    mbedtls_debug_set_threshold( MBEDTLS_DEBUG_LEVEL );
    mbedtls_net_init( &_net_ctx );
    mbedtls_ssl_init( &_ssl_ctx );
    mbedtls_ssl_config_init( &_ssl_conf );
    mbedtls_x509_crt_init( &_ca );
    mbedtls_ctr_drbg_init( &_ctr_drbg_ctx );
    
    mbedtls_entropy_init( &_entropy );
    if( mbedtls_ctr_drbg_seed( &_ctr_drbg_ctx, mbedtls_entropy_func, &_entropy, NULL, 0 ) != 0 )
    {
        qCWarning(catQSslSocketBackendPrivate, "mbedtls_ctr_drbg_seed failed !");
        emit q->error(q->SocketError::SslInternalError);
    }
    
    int ret = mbedtls_x509_crt_parse_path( &_ca, "/usr/share/ca-certificates/mozilla" );
    if( ret < 0 )
    {
        qCWarning(catQSslSocketBackendPrivate, "mbedtls_x509_crt_parse_path failed !");
        QSslError error(QSslError::InvalidCaCertificate);
        sslErrors += error;
        emit q->sslErrors(sslErrors);
    }
    else if (ret > 0)
    {
        qCWarning(catQSslSocketBackendPrivate,
            "Warning : mbedtls_x509_crt_parse_path error while loading %d of the certificates from %s",
            ret, "/usr/share/ca-certificates/mozilla");
    }
    
    ensureInitialized();
    if (MBEDTLS_DEBUG_LEVEL)
        qCWarning(catQSslSocketBackendPrivate, "Leaving QSslSocketBackendPrivate()");
}

QSslSocketBackendPrivate::~QSslSocketBackendPrivate()
{
    if (MBEDTLS_DEBUG_LEVEL)
        qCWarning(catQSslSocketBackendPrivate, "Entering ~QSslSocketBackendPrivate()");
    mbedtls_ssl_free( &_ssl_ctx );
    mbedtls_ssl_config_free( &_ssl_conf );
    mbedtls_ctr_drbg_free( &_ctr_drbg_ctx );
    mbedtls_entropy_free( &_entropy );
    mbedtls_x509_crt_free( &_ca );
    if (MBEDTLS_DEBUG_LEVEL)
        qCWarning(catQSslSocketBackendPrivate, "Leaving ~QSslSocketBackendPrivate()");
}

void QSslSocketBackendPrivate::startClientEncryption()
{
    if (MBEDTLS_DEBUG_LEVEL)
        qCWarning(catQSslSocketBackendPrivate, "Entering startClientEncryption()");
    if (connectionEncrypted)
    {
        if (MBEDTLS_DEBUG_LEVEL)
            qCWarning(catQSslSocketBackendPrivate, "Early leaving startClientEncryption()");
        return; // let's not mess up the connection...
    }
	
    connectionEncrypted = false;
    continueHandshake();

    connectionEncrypted = true;
    Q_Q(QSslSocket);
    emit q->encrypted();
    if (MBEDTLS_DEBUG_LEVEL)
        qCWarning(catQSslSocketBackendPrivate, "Leaving startClientEncryption()");
}

void QSslSocketBackendPrivate::startServerEncryption()
{
    if (MBEDTLS_DEBUG_LEVEL)
        qCWarning(catQSslSocketBackendPrivate, "Entering startServerEncryption()");
    Q_UNIMPLEMENTED();
    if (MBEDTLS_DEBUG_LEVEL)
        qCWarning(catQSslSocketBackendPrivate, "Leaving startServerEncryption()");
}

void QSslSocketBackendPrivate::transmit()
{
    if (MBEDTLS_DEBUG_LEVEL)
        qCWarning(catQSslSocketBackendPrivate, "Entering transmit()");
    Q_Q(QSslSocket);

    if (connectionEncrypted && !writeBuffer.isEmpty())
    {
        qint64 totalBytesWritten = 0;
        int nextDataBlockSize;
        while ((nextDataBlockSize = writeBuffer.nextDataBlockSize()) > 0)
        {
            char* writeBuf = (char*)(malloc(sizeof(char) * (nextDataBlockSize + 1)));
            memcpy(writeBuf, writeBuffer.readPointer(), nextDataBlockSize);
            writeBuf[nextDataBlockSize] = 0;
            if (MBEDTLS_DEBUG_LEVEL)
                qCWarning(catQSslSocketBackendPrivate, "mbedtls_ssl_write() about to send : [[%s]] (len %d)", writeBuf, nextDataBlockSize);
            int writtenBytes;
            if ((writtenBytes = mbedtls_ssl_write( &_ssl_ctx, reinterpret_cast<const unsigned char*>(writeBuf), nextDataBlockSize )) <= 0 )
            {
                emit q->error(q->SocketError::SocketAccessError);
            }
            if (MBEDTLS_DEBUG_LEVEL)
                qCWarning(catQSslSocketBackendPrivate, "mbedtls_ssl_write() sent %d bytes of %d", writtenBytes, nextDataBlockSize);
            writtenBytes = nextDataBlockSize;

            writeBuffer.free(writtenBytes);
            totalBytesWritten += writtenBytes;

            if (writtenBytes < nextDataBlockSize)
                break;
        }

        if (totalBytesWritten > 0)
        {
            // Don't emit bytesWritten() recursively.
            if (!emittedBytesWritten)
            {
                emittedBytesWritten = true;
                emit q->bytesWritten(totalBytesWritten);
                emittedBytesWritten = false;
            }
            emit q->channelBytesWritten(0, totalBytesWritten);
        }
    }

    mbedtls_ssl_conf_read_timeout( &_ssl_conf, 200 );
    
    // Read data to from the socket.
    bool bytesRead = false;
    int bytesToRead = 4096;
    int totalBytesRead = 0;
    QByteArray temp;
    do
    {
        int ret = mbedtls_ssl_read( &_ssl_ctx, reinterpret_cast<unsigned char*>(buffer.reserve(bytesToRead)), bytesToRead );

        if( ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE )
            continue;

        if( ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY || ret == MBEDTLS_ERR_SSL_TIMEOUT )
        {
            char error_buf[100];
            mbedtls_strerror( ret, error_buf, 100 );
            if (MBEDTLS_DEBUG_LEVEL)
                qCWarning(catQSslSocketBackendPrivate, "mbedtls_ssl_read() got \"%s\" (-0x%x).", error_buf , -ret );
            q->disconnectFromHost();
            pendingClose = false;
            break;
        }

        if( ret < 0 )
        {
            char error_buf[100];
            mbedtls_strerror( ret, error_buf, 100 );
            qCWarning(catQSslSocketBackendPrivate, "mbedtls_ssl_read() failed ! It returned \"%s\" (-0x%x)", error_buf, -ret );
            q->disconnectFromHost();
            pendingClose = false;
            break;
        }

        if( ret == 0 )
        {
            if (MBEDTLS_DEBUG_LEVEL)
                qCWarning(catQSslSocketBackendPrivate, "mbedtls_ssl_read() got EOF, it received %d bytes.", totalBytesRead );
            pendingClose = true;
            break;
        }
        
        if (MBEDTLS_DEBUG_LEVEL)
            qCWarning(catQSslSocketBackendPrivate, "mbedtls_ssl_read() received %d bytes", ret);
        
        buffer.chop(bytesToRead - ret);
        
        bytesRead = true;
        totalBytesRead += ret;
    }
    while( 1 );
    
    //buffer.chop(bytesToRead);
    if (bytesRead)
    {        
        if (MBEDTLS_DEBUG_LEVEL)
            qCWarning(catQSslSocketBackendPrivate, "Total of %d bytes received.", totalBytesRead);
        
        if (readyReadEmittedPointer)
            *readyReadEmittedPointer = true;
        emit q->readyRead();
        emit q->channelReadyRead(0);
    }

    if (pendingClose)
    {
        q->disconnectFromHost();
        pendingClose = false;
    }
    if (MBEDTLS_DEBUG_LEVEL)
        qCWarning(catQSslSocketBackendPrivate, "Leaving transmit()");
}

void QSslSocketBackendPrivate::disconnectFromHost()
{
    if (MBEDTLS_DEBUG_LEVEL)
        qCWarning(catQSslSocketBackendPrivate, "Entering disconnectFromHost()");
    mbedtls_ssl_close_notify( &_ssl_ctx );
    if (plainSocket->state() != QAbstractSocket::UnconnectedState)
        plainSocket->disconnectFromHost();
    if (MBEDTLS_DEBUG_LEVEL)
        qCWarning(catQSslSocketBackendPrivate, "Leaving disconnectFromHost()");
}

void QSslSocketBackendPrivate::disconnected()
{
    if (MBEDTLS_DEBUG_LEVEL)
        qCWarning(catQSslSocketBackendPrivate, "Entering disconnected()");
    shutdown = true;
	connectionEncrypted = false;
    if (MBEDTLS_DEBUG_LEVEL)
        qCWarning(catQSslSocketBackendPrivate, "Leaving disconnected()");
}

QSslCipher QSslSocketBackendPrivate::sessionCipher() const
{
    if (MBEDTLS_DEBUG_LEVEL)
    {
        qCWarning(catQSslSocketBackendPrivate, "Entering sessionCipher()");
        qCWarning(catQSslSocketBackendPrivate, "Leaving sessionCipher()");
    }
    return configuration.sessionCipher;
}

QSsl::SslProtocol QSslSocketBackendPrivate::sessionProtocol() const
{
    if (MBEDTLS_DEBUG_LEVEL)
    {
        qCWarning(catQSslSocketBackendPrivate, "Entering sessionProtocol()");
        qCWarning(catQSslSocketBackendPrivate, "Leaving sessionProtocol()");
    }
    return configuration.sessionCipher.protocol();
}

void QSslSocketBackendPrivate::continueHandshake()
{
    if (MBEDTLS_DEBUG_LEVEL)
        qCWarning(catQSslSocketBackendPrivate, "Entering continueHandshake()");
    
    Q_Q(QSslSocket);
    
    size_t bufsize = plainSocket->peerName().length() + 1;
    char* peerName = (char*)malloc( sizeof(char*) * bufsize);
    strncpy( peerName, plainSocket->peerName().toStdString().c_str(), bufsize );
    
    std::string pp = std::to_string( plainSocket->peerPort() );
    bufsize = pp.length() + 1;
    char* peerPortNum = (char*)malloc( sizeof(char*) * bufsize);
    strncpy( peerPortNum, pp.c_str(), bufsize );
    
    
    if (MBEDTLS_DEBUG_LEVEL)
        qCWarning(catQSslSocketBackendPrivate, "About to mbedtls_net_connect to hostname '%s' : port '%s'", peerName, peerPortNum);
    int res;
    if( ( res = mbedtls_net_connect( &_net_ctx, peerName, peerPortNum, MBEDTLS_NET_PROTO_TCP ) ) != 0 )
    {
        char buff[255];
        mbedtls_strerror(res, buff,255);
        qCWarning(catQSslSocketBackendPrivate, "mbedtls_net_connect failed ! It returned -0x%x (%s)", -res, buff);
        emit q->error(q->SocketError::NetworkError);
    }
    
    free( peerPortNum );
    // Now this is an ugly hack we might want to remove later on once we get out of POC mode : closing and reopening the socket.
    close( cachedSocketDescriptor );
    plainSocket->setSocketDescriptor(_net_ctx.fd);
    cachedSocketDescriptor = _net_ctx.fd;
    
    if( mbedtls_ssl_config_defaults( &_ssl_conf,
                MBEDTLS_SSL_IS_CLIENT,
                MBEDTLS_SSL_TRANSPORT_STREAM,
                MBEDTLS_SSL_PRESET_DEFAULT ) != 0 )
    {
        qCWarning(catQSslSocketBackendPrivate, "mbedtls_ssl_config_defaults failed !");
        emit q->error(q->SocketError::SslInternalError);
    }

    mbedtls_ssl_conf_authmode( &_ssl_conf, MBEDTLS_SSL_VERIFY_REQUIRED );
    mbedtls_ssl_conf_ca_chain( &_ssl_conf, &_ca, NULL );
    mbedtls_ssl_conf_rng( &_ssl_conf, mbedtls_ctr_drbg_random, &_ctr_drbg_ctx );
    mbedtls_ssl_conf_dbg( &_ssl_conf, our_debug, stdout );


    if( mbedtls_ssl_setup( &_ssl_ctx, &_ssl_conf ) != 0 )
    {
        qCWarning(catQSslSocketBackendPrivate, "mbedtls_ssl_setup failed !");
        emit q->error(q->SocketError::SslInternalError);
    }
    
    if (MBEDTLS_DEBUG_LEVEL)
        qCWarning(catQSslSocketBackendPrivate, "About to mbedtls_ssl_set_hostname to '%s'", peerName);
    if( mbedtls_ssl_set_hostname( &_ssl_ctx, peerName ) != 0 )
    {
        qCWarning(catQSslSocketBackendPrivate, "mbedtls_ssl_set_hostname failed !");
        emit q->error(q->SocketError::SslInternalError);
    }
    
    free( peerName );
    
    mbedtls_ssl_set_bio( &_ssl_ctx, &_net_ctx, mbedtls_net_send, mbedtls_net_recv, mbedtls_net_recv_timeout );
    mbedtls_ssl_set_timer_cb( &_ssl_ctx, &_timer, mbedtls_timing_set_delay, mbedtls_timing_get_delay );
    
    while( ( res = mbedtls_ssl_handshake( &_ssl_ctx ) ) != 0 )
    {
        if (res != MBEDTLS_ERR_SSL_WANT_READ && res != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            char buff[255];
            mbedtls_strerror(res, buff,255);
            qCWarning(catQSslSocketBackendPrivate, "ssl_handshake failed : returned -0x%x (%s)", -res, buff);
            emit q->error(q->SocketError::SslHandshakeFailedError);
            break;
        }
    }
    
    if (MBEDTLS_DEBUG_LEVEL)
        qCWarning(catQSslSocketBackendPrivate, "Verifying peer X.509 certificate..." );
    uint32_t flags;
    if( (flags = mbedtls_ssl_get_verify_result( &_ssl_ctx )) != 0 )
    {
        char vrfy_buf[512];
        mbedtls_x509_crt_verify_info( vrfy_buf, sizeof( vrfy_buf ), "  ! ", flags );
        qCWarning(catQSslSocketBackendPrivate, "mbedtls_ssl_get_verify_result failed : \"%s\"", vrfy_buf );
        QSslError error(QSslError::UnableToVerifyFirstCertificate);
        sslErrors += error;
        emit q->sslErrors(sslErrors);
        emit q->error(q->SocketError::SslHandshakeFailedError);
    }
    else
    {
        if (MBEDTLS_DEBUG_LEVEL)
            qCWarning(catQSslSocketBackendPrivate, "mbedtls_ssl_get_verify_result succeded.");
    }
    
    if (MBEDTLS_DEBUG_LEVEL)
        qCWarning(catQSslSocketBackendPrivate, "Leaving continueHandshake()");
}
    
QList<QSslCipher> QSslSocketBackendPrivate::defaultCiphers()
{
    if (MBEDTLS_DEBUG_LEVEL)
        qCWarning(catQSslSocketBackendPrivate, "Entering defaultCiphers()");
    const QString protocolStrings[] = { QStringLiteral("SSLv3"), QStringLiteral("TLSv1"),
                                        QStringLiteral("TLSv1.1"), QStringLiteral("TLSv1.2") };
    const QSsl::SslProtocol protocols[] = { QSsl::SslV3, QSsl::TlsV1_0, QSsl::TlsV1_1, QSsl::TlsV1_2 };
    const int size = static_cast<int>(sizeof(protocols) / sizeof(*(protocols)));
    QList<QSslCipher> ciphers;
    ciphers.reserve(size);
    for (int i = 0; i < size; ++i) {
        QSslCipher cipher;
        cipher.d->isNull = false;
        cipher.d->name = QStringLiteral("mbedTLS");
        cipher.d->protocol = protocols[i];
        cipher.d->protocolString = protocolStrings[i];
        ciphers.append(cipher);
    }
    
    if (MBEDTLS_DEBUG_LEVEL)
        qCWarning(catQSslSocketBackendPrivate, "Leaving defaultCiphers()");
    return ciphers;
}

QList<QSslError> QSslSocketBackendPrivate::verify(const QList<QSslCertificate> &certificateChain, const QString &hostName)
{
    if (MBEDTLS_DEBUG_LEVEL)
        qCWarning(catQSslSocketBackendPrivate, "Entering verify()");
    Q_UNIMPLEMENTED();
    Q_UNUSED(certificateChain)
    Q_UNUSED(hostName)
    
    QList<QSslError> errors;

    if (MBEDTLS_DEBUG_LEVEL)
        qCWarning(catQSslSocketBackendPrivate, "Leaving verify()");
    return errors;
}


bool QSslSocketBackendPrivate::importPkcs12(QIODevice *device, QSslKey *key, QSslCertificate *cert,
                                             QList<QSslCertificate> *caCertificates, const QByteArray &passPhrase)
{
    if (MBEDTLS_DEBUG_LEVEL)
        qCWarning(catQSslSocketBackendPrivate, "Entering importPkcs12()");
    Q_UNIMPLEMENTED();
    Q_UNUSED(device)
    Q_UNUSED(key)
    Q_UNUSED(cert)
    Q_UNUSED(caCertificates)
    Q_UNUSED(passPhrase)
    
    if (MBEDTLS_DEBUG_LEVEL)
        qCWarning(catQSslSocketBackendPrivate, "Leaving importPkcs12()");
    return false;
}

QT_END_NAMESPACE
