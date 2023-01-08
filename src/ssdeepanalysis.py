from datetime import datetime
import json

import ssdeep

from machina.core.worker import Worker

class SSDeepAnalysis(Worker):
    
    types = ['*']
    next_queues = ['SimilarityAnalysis']

    def __init__(self, *args, **kwargs):
        super(SSDeepAnalysis, self).__init__(*args, **kwargs)

    def callback(self, data, properties):
        data = json.loads(data)

        # resolve path
        target = self.get_binary_path(data['ts'], data['hashes']['md5'])
        self.logger.info(f"resolved path: {target}")

        # Compute SSDeep Hash
        with open(target, 'rb') as f:
            ssdeep_hash = ssdeep.hash(f.read())

        self.logger.info(f"ssdeep for {target} is {ssdeep_hash}")

        image_cls = self.resolve_db_node_cls(data['type'])
        obj = image_cls.nodes.get(uid=data['uid'])
        obj.ssdeep = ssdeep_hash
        obj.save()

        body = json.dumps({
            'ts': datetime.now().strftime("%Y%m%d%H%M%S%f"),
            'uid': data['uid'],
            'hashes': data['hashes'],
            'type': data['type']
        })

        # Publishes direct to next_queues
        self.publish_next(body)