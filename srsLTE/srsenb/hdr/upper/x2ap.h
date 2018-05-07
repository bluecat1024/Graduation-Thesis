#ifndef X2AP_H
#define X2AP_H

#include "srslte/common/threads.h"
#include "srslte/common/log.h"
#include "srslte/common/buffer_pool.h"
#include "srslte/interfaces/enb_interfaces.h"

#include "srslte/asn1/liblte_x2ap.h"
#include "upper/x2ap_metrics.h"

namespace srsenb
{

typedef struct 
{
	uint32_t      enb_id;     // 20-bit id (lsb bits)
	uint32_t      pci;
	uint8_t       cell_id;    // 8-bit cell id 
	uint16_t      tac;        // 16-bit tac
	uint16_t      mcc;        // BCD-coded with 0xF filler
	uint16_t      mnc;        // BCD-coded with 0xF filler
	uint8_t       active_status; // 0: passive connect 1: active connect
	std::string   neighbour_addr;
	std::string   gtp_bind_addr;
}x2ap_args_t;

class x2ap
	: public x2ap_interface_rrc
	, public thread
{
public:
	bool init(x2ap_args_t args_, rrc_interface_x2ap *rrc_, srslte::log *x2ap_log_);
	void stop();
	void get_metrics(x2ap_metrics_t &m);

	void run_thread();

private:
	static const int X2AP_THREAD_PRIO = 65;
	static const int X2AP_PORT        = 12901;
	static const int ADDR_FAMILY      = AF_INET;
	static const int SOCK_TYPE        = SOCK_STREAM;
	static const int PROTO            = IPPROTO_SCTP;
	static const int PPID             = 20;
	static const int NONUE_STREAM_ID  = 0;

	rrc_interface_x2ap         *rrc;
	x2ap_args_t                args;
	srslte::log                *x2ap_log;
	srslte::byte_buffer_pool   *pool;

	bool neighbour_connected; // whether connected to a neighbour ENB
	bool running;
	int socket_fd, conn_fd;
	struct sockaddr_in neighbour_enb_addr; // Neighbour ENB address

	bool connect_neighbour();
	bool setup_x2ap();

	bool handle_x2ap_rx_pdu(srslte::byte_buffer_t *pdu);
};

} // namespace srsenb
#endif