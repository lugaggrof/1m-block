#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnet.h>
#include <vector>
#include <string>
#include <iostream>
#include <algorithm>
#include <regex>

using namespace std;

vector<string> hosts;

bool str_binary_search(const vector<string>& sorted_vec, string key) {
   size_t mid, left = 0 ;
   size_t right = sorted_vec.size(); // one position passed the right end
   while (left < right) {
      mid = left + (right - left)/2;
	  cout << sorted_vec[mid] << (key == sorted_vec[mid] ? "true" : "false") << '\n';

      if (key > sorted_vec[mid]) {
        left = mid+1;
      } else if (key < sorted_vec[mid]) {
        right = mid;
      } else {
		return true;
	  }
	}

   return false;      
}

int check(unsigned char *data) {
	// check is ipv4
	struct libnet_ipv4_hdr* ipv4_hdr = (struct libnet_ipv4_hdr*)data;
	if(ipv4_hdr->ip_v != 4 || ipv4_hdr->ip_hl != 5) {
		return 0;
	}
	const char *host_prefix = "Host: ";
	// check data host == host
	data += sizeof(struct libnet_ipv4_hdr);
	data += sizeof(struct libnet_tcp_hdr);
	char* data_host = strstr(reinterpret_cast<char*>(data), host_prefix);

	if(data_host != NULL) {
		data_host += strlen(host_prefix);

		string str_data_host(data_host);
		str_data_host = str_data_host.substr(0, str_data_host.find("\n") - 1);

		cout << "host: " << str_data_host << '\n';
		bool is_find = str_binary_search(hosts, str_data_host);
		cout << is_find << '\n';
		if (is_find) {
			printf("%s detected, drop\n", data_host);
			return 1;
		}
	}
	return 0;
}

/* returns packet id */
static u_int32_t is_pkt_match(struct nfq_data *tb, int *is_check)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi;
	int ret;
	unsigned char *data;
	char *data_;
	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
	}

	ret = nfq_get_payload(tb, &data);
	*is_check = check(data);

	return id;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	int is_check;
	u_int32_t id = is_pkt_match(nfa, &is_check);
	
	return nfq_set_verdict(qh, id, is_check ? NF_DROP : NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	if (argc != 2) {
		printf("syntax : 1m-block <site list file>\nsample : 1m-block top-1m.txt\n");
		exit(1);
	}


	FILE *fp;
    char *line = NULL;
    size_t len = 0;
    ssize_t read;

	fp = fopen(argv[1], "r");
	if (fp == NULL) exit(EXIT_FAILURE);

	int cnt = 0;

    while ((read = getline(&line, &len, fp)) != -1) {
        string str(line);
		string host = str.substr(str.find(',') + 1);
		host = regex_replace(host,std::regex("\\r\\n|\\r|\\n"),"");
		cout << host;
		hosts.push_back(host);
		cnt++;
		if (cnt > 40) break;
    }
	fclose(fp);
	sort(hosts.begin(), hosts.end());
	for (auto host: hosts) {
		cout << host;
	}
	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
