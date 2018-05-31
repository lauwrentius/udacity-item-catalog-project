# import boto
import botocore
# import sys
# from boto.s3.key import Key

# AWS_ACCESS_KEY_ID = ''
# AWS_SECRET_ACCESS_KEY = ''
#
# bucket_name = AWS_ACCESS_KEY_ID.lower() + '-dump'
# conn = boto.connect_s3(AWS_ACCESS_KEY_ID,
#         AWS_SECRET_ACCESS_KEY)
#
#
# bucket = conn.create_bucket(bucket_name,
#     location=boto.s3.connection.Location.DEFAULT)
#
# testfile = "./testing_uploads.jpg"
#
# print 'Uploading %s to Amazon S3 bucket %s' % \
#    (testfile, bucket_name)
#
# def percent_cb(complete, total):
#     sys.stdout.write('.')
#     sys.stdout.flush()
#
#
# k = Key(bucket)
# k.key = 'my test file'
# k.set_contents_from_filename(testfile,
#     cb=percent_cb, num_cb=10)

import boto3
import botocore

s3 = boto3.resource('s3')
bucket = s3.Bucket('elasticbeanstalk-us-west-2-369336360970')
exists = True
try:
    s3.meta.client.head_bucket(Bucket='elasticbeanstalk-us-west-2-369336360970')
    print(bucket)

except botocore.exceptions.ClientError as e:
    # If a client error is thrown, then check that it was a 404 error.
    # If it was a 404 error, then the bucket does not exist.
    error_code = int(e.response['Error']['Code'])
    if error_code == 404:
        exists = False


#http://elasticbeanstalk-us-west-2-369336360970.s3.amazonaws.com/item-catalog-uploads/Rock-Climbing-Rope.jpg
