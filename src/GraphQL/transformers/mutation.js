import Parse from 'parse/node';
import { fromGlobalId } from 'graphql-relay';
import { handleUpload } from '../loaders/filesMutations';
import * as objectsMutations from '../helpers/objectsMutations';

const transformTypes = async (
  inputType: 'create' | 'update',
  fields,
  { className, parseGraphQLSchema, req, originalFields }
) => {
  const {
    classGraphQLCreateType,
    classGraphQLUpdateType,
    config: { isCreateEnabled, isUpdateEnabled },
  } = parseGraphQLSchema.parseClassTypes[className];
  const parseClass = parseGraphQLSchema.parseClasses[className];
  if (fields) {
    const classGraphQLCreateTypeFields =
      isCreateEnabled && classGraphQLCreateType ? classGraphQLCreateType.getFields() : null;
    const classGraphQLUpdateTypeFields =
      isUpdateEnabled && classGraphQLUpdateType ? classGraphQLUpdateType.getFields() : null;
    const promises = Object.keys(fields).map(async field => {
      let inputTypeField;
      if (inputType === 'create' && classGraphQLCreateTypeFields) {
        inputTypeField = classGraphQLCreateTypeFields[field];
      } else if (classGraphQLUpdateTypeFields) {
        inputTypeField = classGraphQLUpdateTypeFields[field];
      }
      if (inputTypeField) {
        const parseFieldType = parseClass.fields[field].type;
        switch (parseFieldType) {
          case 'GeoPoint':
            if (fields[field] === null) {
              fields[field] = { __op: 'Delete' };
              break;
            }
            fields[field] = transformers.geoPoint(fields[field]);
            break;
          case 'Polygon':
            if (fields[field] === null) {
              fields[field] = { __op: 'Delete' };
              break;
            }
            fields[field] = transformers.polygon(fields[field]);
            break;
          case 'File':
            // We need to use the originalFields to handle the file upload
            // since fields are a deepcopy and do not keep the file object
            fields[field] = await transformers.file(originalFields[field], req);
            break;
          case 'Relation':
            fields[field] = await transformers.relation(
              parseClass.fields[field].targetClass,
              field,
              fields[field],
              originalFields[field],
              parseGraphQLSchema,
              req
            );
            break;
          case 'Pointer':
            if (fields[field] === null) {
              fields[field] = { __op: 'Delete' };
              break;
            }
            fields[field] = await transformers.pointer(
              parseClass.fields[field].targetClass,
              field,
              fields[field],
              originalFields[field],
              parseGraphQLSchema,
              req
            );
            break;
          default:
            if (fields[field] === null) {
              fields[field] = { __op: 'Delete' };
              return;
            }
            break;
        }
      }
    });
    await Promise.all(promises);
    if (fields.ACL) { fields.ACL = transformers.ACL(fields.ACL); }
  }
  return fields;
};

const transformers = {
  file: async (input, { config }) => {
    if (input === null) {
      return { __op: 'Delete' };
    }
    const { file, upload } = input;
    if (upload) {
      const { fileInfo } = await handleUpload(upload, config);
      return { ...fileInfo, __type: 'File' };
    } else if (file && file.name) {
      return { name: file.name, __type: 'File', url: file.url };
    }
    throw new Parse.Error(Parse.Error.FILE_SAVE_ERROR, 'Invalid file upload.');
  },
  polygon: value => ({
    __type: 'Polygon',
    coordinates: value.map(geoPoint => [geoPoint.latitude, geoPoint.longitude]),
  }),
  geoPoint: value => ({
    ...value,
    __type: 'GeoPoint',
  }),
  ACL: value => {
    const parseACL = {};
    if (value.public) {
      parseACL['*'] = {
        read: value.public.read,
        write: value.public.write,
      };
    }
    if (value.users) {
      value.users.forEach(rule => {
        const globalIdObject = fromGlobalId(rule.userId);
        if (globalIdObject.type === '_User') {
          rule.userId = globalIdObject.id;
        }
        parseACL[rule.userId] = {
          read: rule.read,
          write: rule.write,
        };
      });
    }
    if (value.roles) {
      value.roles.forEach(rule => {
        parseACL[`role:${rule.roleName}`] = {
          read: rule.read,
          write: rule.write,
        };
      });
    }
    return parseACL;
  },
  relation: async (
    targetClass,
    field,
    value,
    originalValue,
    parseGraphQLSchema,
    { config, auth, info }
  ) => {
    if (Object.keys(value).length === 0)
    { throw new Parse.Error(
      Parse.Error.INVALID_POINTER,
      `You need to provide at least one operation on the relation mutation of field ${field}`
    ); }

    const op = {
      __op: 'Batch',
      ops: [],
    };
    let nestedObjectsToAdd = [];

    if (value.createAndAdd) {
      nestedObjectsToAdd = (
        await Promise.all(
          value.createAndAdd.map(async (input, i) => {
            const parseFields = await transformTypes('create', input, {
              className: targetClass,
              originalFields: originalValue.createAndAdd[i],
              parseGraphQLSchema,
              req: { config, auth, info },
            });
            return objectsMutations.createObject(targetClass, parseFields, config, auth, info);
          })
        )
      ).map(object => ({
        __type: 'Pointer',
        className: targetClass,
        objectId: object.objectId,
      }));
    }

    if (value.add || nestedObjectsToAdd.length > 0) {
      if (!value.add) { value.add = []; }
      value.add = value.add.map(input => {
        const globalIdObject = fromGlobalId(input);
        if (globalIdObject.type === targetClass) {
          input = globalIdObject.id;
        }
        return {
          __type: 'Pointer',
          className: targetClass,
          objectId: input,
        };
      });
      op.ops.push({
        __op: 'AddRelation',
        objects: [...value.add, ...nestedObjectsToAdd],
      });
    }

    if (value.remove) {
      op.ops.push({
        __op: 'RemoveRelation',
        objects: value.remove.map(input => {
          const globalIdObject = fromGlobalId(input);
          if (globalIdObject.type === targetClass) {
            input = globalIdObject.id;
          }
          return {
            __type: 'Pointer',
            className: targetClass,
            objectId: input,
          };
        }),
      });
    }
    return op;
  },
  pointer: async (
    targetClass,
    field,
    value,
    originalValue,
    parseGraphQLSchema,
    { config, auth, info }
  ) => {
    if (Object.keys(value).length > 1 || Object.keys(value).length === 0)
    { throw new Parse.Error(
      Parse.Error.INVALID_POINTER,
      `You need to provide link OR createLink on the pointer mutation of field ${field}`
    ); }

    let nestedObjectToAdd;
    if (value.createAndLink) {
      const parseFields = await transformTypes('create', value.createAndLink, {
        className: targetClass,
        parseGraphQLSchema,
        originalFields: originalValue.createAndLink,
        req: { config, auth, info },
      });
      nestedObjectToAdd = await objectsMutations.createObject(
        targetClass,
        parseFields,
        config,
        auth,
        info
      );
      return {
        __type: 'Pointer',
        className: targetClass,
        objectId: nestedObjectToAdd.objectId,
      };
    }
    if (value.link) {
      let objectId = value.link;
      const globalIdObject = fromGlobalId(objectId);
      if (globalIdObject.type === targetClass) {
        objectId = globalIdObject.id;
      }
      return {
        __type: 'Pointer',
        className: targetClass,
        objectId,
      };
    }
  },
};

export { transformTypes };
