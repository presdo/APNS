module APNS
  require 'socket'
  require 'openssl'
  require 'json'

  @host = 'gateway.sandbox.push.apple.com'
  @port = 2195

  class << self
    attr_accessor :host, :port
  end

  def self.send_notification(pem, password, device_token, message)
    n = APNS::Notification.new(device_token, message)

    sock, ssl = self.open_connection(pem, password)

    packed_notifications = self.packed_notifications([n])

    ssl.write(packed_notifications)

    ssl.close
    sock.close
  end

  def self.packed_notifications(notifications)
    bytes = ''

    notifications.each do |notification|
      # Each notification frame consists of
      # 1. (e.g. protocol version) 2 (unsigned char [1 byte]) 
      # 2. size of the full frame (unsigend int [4 byte], big endian)
      pn = notification.packaged_notification
      bytes << ([2, pn.bytesize].pack('CN') + pn)
    end

    bytes
  end

  def self.feedback
    sock, ssl = self.feedback_connection

    apns_feedback = []

    while message = ssl.read(38)
      timestamp, token_size, token = message.unpack('N1n1H*')
      apns_feedback << [Time.at(timestamp), token]
    end

    ssl.close
    sock.close

    return apns_feedback
  end

  protected

  def self.open_connection(pem, password)
    raise "The path to your pem file is not set. (APNS.pem = /path/to/cert.pem)" unless pem
    raise "The path to your pem file does not exist!" unless File.exist?(pem)

    context      = OpenSSL::SSL::SSLContext.new
    context.cert = OpenSSL::X509::Certificate.new(File.read(pem))
    context.key  = OpenSSL::PKey::RSA.new(File.read(pem), password)

    sock         = TCPSocket.new(self.host, self.port)
    ssl          = OpenSSL::SSL::SSLSocket.new(sock,context)
    ssl.connect

    return sock, ssl
  end

  def self.feedback_connection(pem, password)
    raise "The path to your pem file is not set. (APNS.pem = /path/to/cert.pem)" unless pem
    raise "The path to your pem file does not exist!" unless File.exist?(pem)

    context      = OpenSSL::SSL::SSLContext.new
    context.cert = OpenSSL::X509::Certificate.new(File.read(pem))
    context.key  = OpenSSL::PKey::RSA.new(File.read(pem), password)

    fhost = self.host.gsub('gateway','feedback')
    puts fhost

    sock         = TCPSocket.new(fhost, 2196)
    ssl          = OpenSSL::SSL::SSLSocket.new(sock,context)
    ssl.connect

    return sock, ssl
  end
end
