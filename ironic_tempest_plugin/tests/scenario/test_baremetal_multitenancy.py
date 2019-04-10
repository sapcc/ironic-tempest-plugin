#
# Copyright (c) 2015 Mirantis, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from tempest.common import utils
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators

from ironic_tempest_plugin import manager
from ironic_tempest_plugin.tests.scenario import baremetal_manager

CONF = config.CONF


class BaremetalMultitenancy(baremetal_manager.BaremetalScenarioTest,
                            manager.NetworkScenarioTest):
    """Check L2 isolation of baremetal and VM instances in different tenants:

    * Create a keypair, network, subnet and router for the primary tenant
    * Boot 2 instances in the different tenant's network using the keypair
    * Associate floating ips to both instance
    * Verify there is no L3 connectivity between instances of different tenants
    * Verify connectivity between instances floating IP's
    * Delete both instances
    """

    credentials = ['primary', 'alt', 'admin']

    @classmethod
    def skip_checks(cls):
        super(BaremetalMultitenancy, cls).skip_checks()
        if not CONF.baremetal.use_provision_network:
            msg = 'Ironic/Neutron tenant isolation is not configured.'
            raise cls.skipException(msg)
        if (CONF.baremetal.available_nodes is not None and
                CONF.baremetal.available_nodes < 2):
            msg = ('Not enough baremetal nodes, %d configured, test requires '
                   'a minimum of 2') % CONF.baremetal.available_nodes
            raise cls.skipException(msg)

    def create_tenant_network(self, clients, tenant_cidr):
        network = self._create_network(
            networks_client=clients.networks_client,
            tenant_id=clients.credentials.tenant_id)
        router = self._get_router(
            client=clients.routers_client,
            tenant_id=clients.credentials.tenant_id)

        result = clients.subnets_client.create_subnet(
            name=data_utils.rand_name('subnet'),
            network_id=network['id'],
            tenant_id=clients.credentials.tenant_id,
            ip_version=4,
            cidr=tenant_cidr)
        subnet = result['subnet']
        clients.routers_client.add_router_interface(router['id'],
                                                    subnet_id=subnet['id'])
        self.addCleanup(clients.subnets_client.delete_subnet, subnet['id'])
        self.addCleanup(clients.routers_client.remove_router_interface,
                        router['id'], subnet_id=subnet['id'])
        return network, subnet, router

    def verify_l3_connectivity(self, source_ip, private_key,
                               destination_ip, conn_expected=True):
        remote = self.get_remote_client(source_ip, private_key=private_key)
        remote.validate_authentication()

        cmd = 'ping %s -c4 -w4 || exit 0' % destination_ip
        success_substring = "64 bytes from %s" % destination_ip
        output = remote.exec_command(cmd)
        if conn_expected:
            self.assertIn(success_substring, output)
        else:
            self.assertNotIn(success_substring, output)

    def multitenancy_check(self, use_vm=False):
        tenant_cidr = '10.0.100.0/24'
        keypair = self.create_keypair()
        network, subnet, router = self.create_tenant_network(
            self.os_primary, tenant_cidr)
        alt_keypair = self.create_keypair(self.os_alt.keypairs_client)
        alt_network, alt_subnet, alt_router = self.create_tenant_network(
            self.os_alt, tenant_cidr)
        # Create single BM guest as Primary
        instance1, node1 = self.boot_instance(
            clients=self.os_primary,
            keypair=keypair,
            net_id=network['id'],
        )
        fixed_ip1 = instance1['addresses'][network['name']][0]['addr']
        floating_ip1 = self.create_floating_ip(
            instance1,
        )['floating_ip_address']
        self.check_vm_connectivity(ip_address=floating_ip1,
                                   private_key=keypair['private_key'])
        if use_vm:
            # Create VM on compute node
            alt_instance = self.create_server(
                clients=self.os_alt,
                key_name=alt_keypair['name'],
                flavor=CONF.compute.flavor_ref_alt,
                networks=[{'uuid': alt_network['id']}]
            )
        else:
            # Create BM
            alt_instance, alt_node = self.boot_instance(
                keypair=alt_keypair,
                clients=self.os_alt,
                net_id=alt_network['id'],
            )
        fixed_ip2 = alt_instance['addresses'][alt_network['name']][0]['addr']
        alt_floating_ip = self.create_floating_ip(
            alt_instance,
            client=self.os_alt.floating_ips_client
        )['floating_ip_address']
        self.check_vm_connectivity(
            ip_address=alt_floating_ip,
            private_key=alt_keypair['private_key'])
        self.verify_l3_connectivity(
            alt_floating_ip,
            alt_keypair['private_key'],
            fixed_ip1,
            conn_expected=False
        )
        self.verify_l3_connectivity(
            floating_ip1,
            keypair['private_key'],
            fixed_ip2,
            conn_expected=False
        )
        self.verify_l3_connectivity(
            floating_ip1,
            keypair['private_key'],
            alt_floating_ip,
            conn_expected=True
        )
        self.terminate_instance(
            instance=alt_instance,
            servers_client=self.os_alt.servers_client)
        self.terminate_instance(instance=instance1)

    @decorators.idempotent_id('26e2f145-2a8e-4dc7-8457-7f2eb2c6749d')
    @utils.services('compute', 'image', 'network')
    def test_baremetal_multitenancy(self):
        self.multitenancy_check()

    @decorators.idempotent_id('9e38631a-2df2-11e9-810e-8c16450ea513')
    @utils.services('compute', 'image', 'network')
    def test_baremetal_vm_multitenancy(self):
        if not CONF.service_available.nova:
            self.skipTest('Compute service Nova is disabled,'
                          ' VM is required to run this test')
        self.multitenancy_check(use_vm=True)
